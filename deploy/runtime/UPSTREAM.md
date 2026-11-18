# Основания runtime и vpn://

Сверено 18.11.2026. Сборка использует:

- amneziawg-go `08fe3d33bbb116be09a6183d02609311b8b0c9e8`: https://github.com/amnezia-vpn/amneziawg-go/tree/08fe3d33bbb116be09a6183d02609311b8b0c9e8
- amneziawg-tools `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843` (`3.1.20260812`): https://github.com/amnezia-vpn/amneziawg-tools/tree/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
- Go 1.26.1, целевая платформа Linux amd64, Alpine 3.22.2 (toolchain image: alpine3.22).

Базовые образы закреплены multiarch manifest digest, проверенными через Docker Hub Registry API. Пакеты apk ещё не закреплены snapshot: фиксированные версии исходников и базовых образов не гарантируют побитовую воспроизводимость всего image. Перед выпуском сохраните построенный image в registry и используйте его immutable digest. Пакеты runtime и воспроизводимость образа входят в приёмочные проверки.

Профиль сверялся с официальным клиентом `5aff2ce5809514ef7c292ac5e7ed3758d7d0b333` (dev):

- `client/core/controllers/selfhosted/exportController.cpp`: qCompress, base64url без padding, префикс vpn://.
- `client/core/controllers/selfhosted/importController.cpp`, `extractWireGuardConfig`: third-party container, числовой `last_config.port`, строковый JSON `last_config` и отдельные поля AWG.
- `client/core/utils/constants/configKeys.h`: `amnezia-awg`, `client_priv_key`, `server_pub_key`, `psk_key`, `allowed_ips`, `persistent_keep_alive`, параметры AWG.
- `client/core/models/protocols/awgProtocolConfig.cpp`: сериализация native config и метаданных.

Ссылки: https://github.com/amnezia-vpn/amnezia-client/tree/5aff2ce5809514ef7c292ac5e7ed3758d7d0b333

Параметры: независимые случайные H1–H4, S1–S4 = 32 (не меньше 12 для HeaderProtectionKey), согласованные HeaderProtectionKey и RandomTrailers на всех репликах и клиентах. DisableCookies оставлен off, чтобы сохранять защиту от handshake flooding. Ключи X25519 генерируются стандартным crypto/ecdh, PSK — crypto/rand; шифрование хранения — AES-256-GCM с привязкой к ID объекта и назначению секрета.

Схема JSON и unit-тесты не подтверждают импорт конкретным выпущенным Android/iOS/desktop клиентом. Заполненная матрица испытаний с номерами версий обязательна до production.

Установка через install.sh сохраняет docker-save архив и использует локальный sha256 image ID. Этот ID одинаков на контроллере и загруженном VPS; публикация собственного образа в registry для такого режима не требуется.
