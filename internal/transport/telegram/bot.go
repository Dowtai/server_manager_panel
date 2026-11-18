package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Bot struct {
	Token, API, ServiceToken string
	HTTP                     *http.Client
	OffsetFile               string
}
type update struct {
	ID       int64     `json:"update_id"`
	Message  *message  `json:"message"`
	Callback *callback `json:"callback_query"`
}
type message struct {
	ID   int64  `json:"message_id"`
	Text string `json:"text"`
	Chat struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	} `json:"chat"`
	From struct {
		ID int64 `json:"id"`
	} `json:"from"`
}
type callback struct {
	ID   string `json:"id"`
	From struct {
		ID int64 `json:"id"`
	} `json:"from"`
	Data    string   `json:"data"`
	Message *message `json:"message"`
}
type userView struct {
	Instances []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Limit int    `json:"limit"`
		Ready bool   `json:"ready"`
	} `json:"instances"`
	Devices []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Revoked bool   `json:"revoked"`
	} `json:"devices"`
}

func (b *Bot) telegram(ctx context.Context, method string, body any, out any) error {
	data, e := json.Marshal(body)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", "https://api.telegram.org/bot"+b.Token+"/"+method, bytes.NewReader(data))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := b.HTTP.Do(req)
	if e != nil {
		return fmt.Errorf("Telegram unavailable")
	}
	defer res.Body.Close()
	var envelope struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&envelope); e != nil || !envelope.OK {
		return fmt.Errorf("Telegram request failed")
	}
	if out != nil {
		return json.Unmarshal(envelope.Result, out)
	}
	return nil
}
func (b *Bot) api(ctx context.Context, user int64, method, path string, body, out any) error {
	var data []byte
	var e error
	if body != nil {
		data, e = json.Marshal(body)
		if e != nil {
			return e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(b.API, "/")+"/api/service"+path, bytes.NewReader(data))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+b.ServiceToken)
	req.Header.Set("X-Telegram-ID", strconv.FormatInt(user, 10))
	req.Header.Set("Content-Type", "application/json")
	res, e := b.HTTP.Do(req)
	if e != nil {
		return fmt.Errorf("backend unavailable")
	}
	defer res.Body.Close()
	data, e = io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if e != nil {
		return e
	}
	if res.StatusCode >= 400 {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &errBody)
		return fmt.Errorf("%s", errBody.Error)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
func (b *Bot) send(ctx context.Context, chat int64, text string, keyboard any) error {
	body := map[string]any{"chat_id": chat, "text": text, "protect_content": true}
	if keyboard != nil {
		body["reply_markup"] = map[string]any{"inline_keyboard": keyboard}
	}
	return b.telegram(ctx, "sendMessage", body, nil)
}
func (b *Bot) Run(ctx context.Context) error {
	if b.HTTP == nil {
		b.HTTP = &http.Client{Timeout: 45 * time.Second}
	}
	offset := int64(0)
	if raw, e := os.ReadFile(b.OffsetFile); e == nil {
		var err error
		offset, err = strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			return fmt.Errorf("invalid Telegram offset file")
		}
	} else if !os.IsNotExist(e) {
		return fmt.Errorf("read Telegram offset failed")
	}
	for ctx.Err() == nil {
		var updates []update
		e := b.telegram(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": 25, "allowed_updates": []string{"message", "callback_query"}}, &updates)
		if e != nil {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(3 * time.Second):
			}
			continue
		}
		for _, u := range updates {
			if e = b.handle(ctx, u); e != nil {
				break
			}
			offset = u.ID + 1
			if e = b.saveOffset(offset); e != nil {
				return e
			}
		}
	}
	return nil
}
func (b *Bot) handle(ctx context.Context, u update) error {
	if u.Callback != nil {
		c := u.Callback
		_ = b.telegram(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": c.ID}, nil)
		if c.Message == nil || c.Message.Chat.Type != "private" || c.Message.Chat.ID != c.From.ID {
			return nil
		}
		var view userView
		if e := b.api(ctx, c.From.ID, "GET", "/me", nil, &view); e != nil {
			return b.send(ctx, c.From.ID, e.Error(), nil)
		}
		if strings.HasPrefix(c.Data, "new:") {
			id := strings.TrimPrefix(c.Data, "new:")
			var d struct {
				ID string `json:"id"`
			}
			e := b.api(ctx, c.From.ID, "POST", "/devices", map[string]string{"instance_id": id, "name": "Устройство " + strconv.FormatInt(u.ID, 10), "request_id": "telegram:" + strconv.FormatInt(u.ID, 10)}, &d)
			if e != nil {
				return b.send(ctx, c.From.ID, e.Error(), nil)
			}
			return b.send(ctx, c.From.ID, "Устройство создано. Дождитесь синхронизации, затем получите профиль: /profile "+d.ID, nil)
		}
		return nil
	}
	m := u.Message
	if m == nil || m.Chat.Type != "private" || m.Chat.ID != m.From.ID {
		return nil
	}
	fields := strings.Fields(m.Text)
	if len(fields) == 0 {
		return nil
	}
	var view userView
	if e := b.api(ctx, m.From.ID, "GET", "/me", nil, &view); e != nil {
		return b.send(ctx, m.Chat.ID, "Доступ не выдан. Обратитесь к администратору.", nil)
	}
	switch strings.Split(fields[0], "@")[0] {
	case "/start", "/help":
		return b.send(ctx, m.Chat.ID, "/instances — доступные instances\n/newkey — создать устройство\n/devices — мои устройства\n/profile ID — скачать vpn://\n/revoke ID — отозвать устройство", nil)
	case "/instances", "/newkey":
		rows := []any{}
		for _, i := range view.Instances {
			label := i.Name
			if !i.Ready {
				label += " · ожидает проверки"
			}
			rows = append(rows, []any{map[string]string{"text": label, "callback_data": "new:" + i.ID}})
		}
		if len(rows) == 0 {
			return b.send(ctx, m.Chat.ID, "Нет доступных instances.", nil)
		}
		return b.send(ctx, m.Chat.ID, "Выберите instance для нового устройства:", rows)
	case "/devices":
		lines := []string{}
		for _, d := range view.Devices {
			status := "активно"
			if d.Revoked {
				status = "отозвано"
			}
			lines = append(lines, d.Name+" · "+status+"\n"+d.ID)
		}
		if len(lines) == 0 {
			lines = append(lines, "Устройств пока нет.")
		}
		text := strings.Join(lines, "\n\n")
		for len(text) > 0 {
			end := min(len(text), 3500)
			for end < len(text) && text[end]&0xc0 == 0x80 {
				end--
			}
			if e := b.send(ctx, m.Chat.ID, text[:end], nil); e != nil {
				return e
			}
			text = text[end:]
		}
		return nil
	case "/profile":
		if len(fields) != 2 {
			return b.send(ctx, m.Chat.ID, "Использование: /profile ID", nil)
		}
		var v struct {
			URL string `json:"url"`
		}
		if e := b.api(ctx, m.From.ID, "GET", "/devices/"+url.PathEscape(fields[1])+"/profile", nil, &v); e != nil {
			return b.send(ctx, m.Chat.ID, e.Error(), nil)
		}
		if len(v.URL) > 4000 {
			return b.send(ctx, m.Chat.ID, "Профиль превышает лимит сообщения. Получите его через администратора в веб-панели.", nil)
		}
		return b.send(ctx, m.Chat.ID, v.URL, nil)
	case "/revoke":
		if len(fields) != 2 {
			return b.send(ctx, m.Chat.ID, "Использование: /revoke ID", nil)
		}
		if e := b.api(ctx, m.From.ID, "DELETE", "/devices/"+url.PathEscape(fields[1]), nil, nil); e != nil {
			return b.send(ctx, m.Chat.ID, e.Error(), nil)
		}
		return b.send(ctx, m.Chat.ID, "Отзыв сохранён. Реплики синхронизируются; недоступные реплики могут сохранять peer до восстановления.", nil)
	default:
		return b.send(ctx, m.Chat.ID, "Используйте /help", nil)
	}
}

func (b *Bot) saveOffset(offset int64) error {
	if e := os.MkdirAll(filepath.Dir(b.OffsetFile), 0700); e != nil {
		return e
	}
	tmp := b.OffsetFile + ".tmp"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.WriteString(strconv.FormatInt(offset, 10))
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, b.OffsetFile)
}
