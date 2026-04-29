# Samizdat VPN — App Icon Handoff

Финальная иконка: **Sigil** — тёмный каменный рельеф башни-ладьи + золотая SZ-монограмма поверх.

## Что в папке `build/`

```
build/
├── AppIcon.svg                      # Векторный мастер-файл (источник правды)
├── AppIcon-1024.png                 # PNG превью на верхнем уровне (для проверки)
└── AppIcon.appiconset/              # Готовый Xcode Asset Catalog set
    ├── Contents.json                # Манифест Xcode
    ├── AppIcon-1024.png             # App Store marketing (1024×1024)
    ├── AppIcon-180.png              # iPhone 60pt @3x
    ├── AppIcon-167.png              # iPad Pro 83.5pt @2x
    ├── AppIcon-152.png              # iPad 76pt @2x
    ├── AppIcon-120.png              # iPhone 60pt @2x / Spotlight 40pt @3x
    ├── AppIcon-87.png               # Settings 29pt @3x
    ├── AppIcon-80.png               # Spotlight 40pt @2x
    ├── AppIcon-76.png               # iPad 76pt @1x
    ├── AppIcon-60.png               # Notification 20pt @3x
    ├── AppIcon-58.png               # Settings 29pt @2x
    ├── AppIcon-40.png               # Notification 20pt @2x / Spotlight 40pt @1x
    ├── AppIcon-29.png               # Settings 29pt @1x
    └── AppIcon-20.png               # Notification 20pt @1x
```

Все PNG не имеют альфа-канала (фон полностью закрашен — обязательное требование App Store).
Squircle-маска применяется системой автоматически — не надо скруглять самим.

## Инструкция для Claude Code

Скопируй и передай Claude Code этот блок как задачу:

---

> Добавь в iOS-приложение новую иконку из папки `build/AppIcon.appiconset/`.
>
> Шаги:
> 1. Найди корневой `Assets.xcassets` основного таргета приложения (обычно `<ProjectName>/Assets.xcassets/`).
> 2. Удали существующий `AppIcon.appiconset` целиком (если есть).
> 3. Скопируй папку `build/AppIcon.appiconset/` (со всем содержимым: `Contents.json` + 13 PNG) в `Assets.xcassets/AppIcon.appiconset/`.
> 4. Открой `project.pbxproj` и убедись, что в build settings таргета:
>    - `ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon`
>    - `ASSETCATALOG_COMPILER_INCLUDE_ALL_APPICON_ASSETS = NO` (по умолчанию)
> 5. Если в Info.plist есть устаревший ключ `CFBundleIcons` с явным списком файлов — удали его, теперь иконки берутся из Asset Catalog.
> 6. Запусти `xcodebuild -project <Project>.xcodeproj -scheme <Scheme> -sdk iphonesimulator build` и убедись, что нет варнингов про missing/oversized icons.
> 7. Открой проект в Xcode (или через `xcrun simctl install`) и проверь, что иконка отображается на симуляторе iPhone — на главном экране, в Spotlight, в Settings, в нотификациях.
>
> Файл `AppIcon.svg` оставь в репозитории как источник правды (рядом с appiconset или в `design/`) — пригодится для будущих ребрендов и для генерации Watch/Mac версий.

---

## Технические детали (на случай вопросов)

- **Размер мастер-PNG для App Store:** 1024×1024, sRGB, без альфа-канала.
- **Цвета:**
  - Фон: градиент `#1a1d28` → `#0a0c14` (тёмный графит)
  - Башня: градиент `#3a4050` → `#1a1e2a` (камень)
  - SZ-монограмма: градиент `#f5d678` → `#c9a04a` → `#7a5a1c` (старое золото)
- **Шрифт SZ-монограммы:** Bodoni 72 / Didot, weight 700, letter-spacing -0.08em. На рендере используется встроенный fallback (Georgia) — для пиксель-перфекта нужно либо встроить Bodoni как WebFont и пересгенерировать PNG, либо растеризовать SVG в Xcode-агенте через rsvg-convert/Inkscape с установленным Bodoni.
- **Минимальная читаемость:** проверена на 60 px (нотификации) — башня и буквы остаются опознаваемыми.

## Если нужна регенерация PNG

Файл `AppIcon.svg` — единственный источник. Перегенерация всех размеров:

```bash
# rsvg-convert (brew install librsvg)
for sz in 1024 180 167 152 120 87 80 76 60 58 40 29 20; do
  rsvg-convert -w $sz -h $sz AppIcon.svg -o AppIcon-${sz}.png
done
```

или через ImageMagick:

```bash
for sz in 1024 180 167 152 120 87 80 76 60 58 40 29 20; do
  magick -background none -density 1200 AppIcon.svg -resize ${sz}x${sz} AppIcon-${sz}.png
done
```
