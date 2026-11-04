# Каталог компонентов фронтенда

Инвентаризация сверена с установленными пакетами проекта: PrimeNG `21.1.10`, Angular CDK `21.2.14`, Angular `21.2.26`. PrimeNG — основной визуальный набор проекта; CDK предоставляет headless-примитивы. Каталог составлен по `frontend/node_modules/primeng/types` и `frontend/node_modules/@angular/cdk/types` 2026-11-04. Ссылки на документацию ведут на [PrimeNG](https://primeng.org/) и [Angular CDK](https://material.angular.dev/cdk/categories).

| Компонент | Назначение | Документация и известное ограничение |
|---|---|---|
| Accordion | Сворачиваемые разделы | [Accordion](https://primeng.org/accordion); проверять клавиатурную навигацию и заголовки |
| AnimateOnScroll | Анимация при прокрутке | [AnimateOnScroll](https://primeng.org/animateonscroll); декоративный эффект не должен скрывать содержимое |
| AutoComplete | Поле с подсказками | [AutoComplete](https://primeng.org/autocomplete); серверные результаты требуется валидировать |
| AutoFocus | Автофокус элемента | [AutoFocus](https://primeng.org/autofocus); избегать перехвата фокуса при навигации |
| Avatar | Изображение или инициалы | [Avatar](https://primeng.org/avatar); задать текстовую альтернативу содержательному изображению |
| AvatarGroup | Группа аватаров | [AvatarGroup](https://primeng.org/avatargroup); длинные группы требуют доступного полного списка |
| Badge | Короткий счётчик или состояние | [Badge](https://primeng.org/badge); значок не должен быть единственным носителем статуса |
| BlockUI | Блокировка области | [BlockUI](https://primeng.org/blockui); не применять как замену понятному состоянию загрузки |
| Breadcrumb | Навигационная цепочка | [Breadcrumb](https://primeng.org/breadcrumb); отражать реальную иерархию |
| Button | Кнопка действия | [Button](https://primeng.org/button); использовать тип button/submit по назначению |
| ButtonGroup | Группа кнопок | [ButtonGroup](https://primeng.org/buttongroup); не объединять несвязанные действия |
| Card | Контейнер содержимого | [Card](https://primeng.org/card); семантику заголовков задаёт приложение |
| Carousel | Прокручиваемый набор карточек | [Carousel](https://primeng.org/carousel); оценить управление клавиатурой и движением |
| CascadeSelect | Иерархический выбор | [CascadeSelect](https://primeng.org/cascadeselect); не подходит для небольшого плоского списка |
| Chart | Диаграммы Chart.js | [Chart](https://primeng.org/chart); требует текстового представления данных |
| Checkbox | Флажок выбора | [Checkbox](https://primeng.org/checkbox); состояние должно иметь видимую подпись |
| Chip | Короткий элемент/метка | [Chip](https://primeng.org/chip); не использовать вместо редактируемой формы |
| ColorPicker | Выбор цвета | [ColorPicker](https://primeng.org/colorpicker); цветовое состояние должно иметь альтернативу |
| ConfirmDialog | Диалог подтверждения | [ConfirmDialog](https://primeng.org/confirmdialog); не использовать для обычных уведомлений |
| ConfirmPopup | Всплывающее подтверждение | [ConfirmPopup](https://primeng.org/confirmpopup); проверить размещение у края окна и фокус |
| ContextMenu | Контекстное меню | [ContextMenu](https://primeng.org/contextmenu); команды должны быть доступны без правой кнопки |
| DataView | Список или сетка записей | [DataView](https://primeng.org/dataview); определить состояния пустого списка и загрузки |
| DatePicker | Выбор даты/времени | [DatePicker](https://primeng.org/datepicker); локаль и часовой пояс задаёт приложение |
| Dialog | Модальный диалог | [Dialog](https://primeng.org/dialog); проверить фокус, Escape и блокировку фонового содержимого |
| Divider | Разделитель | [Divider](https://primeng.org/divider); декоративный разделитель не должен добавлять шум экранному диктору |
| Dock | Панель быстрых ссылок | [Dock](https://primeng.org/dock); учитывать небольшие экраны и подписи иконок |
| DragDrop | Перетаскивание | [DragDrop](https://primeng.org/dragdrop); обязательна альтернативная клавиатурная перестановка |
| Drawer | Выдвижная панель | [Drawer](https://primeng.org/drawer); проверить фокус и режим модальности |
| DynamicDialog | Диалог с динамическим содержимым | [DynamicDialog](https://primeng.org/dynamicdialog); содержимое следует типизировать и явно закрывать |
| Editor | Редактор форматированного текста | [Editor](https://primeng.org/editor); санитизировать HTML и учитывать зависимость редактора |
| Fieldset | Группа полей с заголовком | [Fieldset](https://primeng.org/fieldset); для формы часто достаточно `fieldset` HTML |
| FileUpload | Выбор/загрузка файлов | [FileUpload](https://primeng.org/fileupload); проверять размер и тип на backend, очищать локальную очередь |
| FloatLabel | Плавающая подпись поля | [FloatLabel](https://primeng.org/floatlabel); проверить контраст и видимость подписи при ошибке |
| Fluid | Растяжение вложенных контролов | [Fluid](https://primeng.org/fluid); влияет на ширину потомков, а не на их семантику |
| Galleria | Галерея изображений | [Galleria](https://primeng.org/galleria); обеспечить альтернативы и управление без указателя |
| IconField | Иконка внутри поля | [IconField](https://primeng.org/iconfield); иконка не заменяет подпись поля |
| Icons | Встроенные значки | [Icons](https://primeng.org/icons); значимые иконки подписывать, набор не является отдельным экранным читателем |
| IftaLabel | Подпись внутри поля с переходом | [IftaLabel](https://primeng.org/iftalabel); проверять читаемость заполненного и сфокусированного поля |
| Image | Просмотр изображения | [Image](https://primeng.org/image); ограничивать источники и описывать содержимое |
| ImageCompare | Сравнение изображений | [ImageCompare](https://primeng.org/imagecompare); требует альтернативы для недоступного жеста |
| Inplace | Редактирование на месте | [Inplace](https://primeng.org/inplace); обеспечить заметный переход между просмотром и редактированием |
| InputGroup | Компоновка поля и связанных действий | [InputGroup](https://primeng.org/inputgroup); сохранять отдельные подписи и фокусируемые кнопки |
| InputGroupAddon | Аддон к группе ввода | [InputGroup](https://primeng.org/inputgroup); декоративный текст не должен выглядеть как часть значения |
| InputIcon | Иконка у поля ввода | [InputIcon](https://primeng.org/inputicon); иконка не заменяет label |
| InputMask | Форматированный ввод | [InputMask](https://primeng.org/inputmask); маска не заменяет серверную валидацию |
| InputNumber | Числовое поле | [InputNumber](https://primeng.org/inputnumber); проверять целочисленность и диапазон на сервере |
| InputOtp | Одноразовый код | [InputOtp](https://primeng.org/inputotp); проверить вставку полного кода и автозаполнение |
| InputText | Текстовое поле | [InputText](https://primeng.org/inputtext); подпись и ошибки задаёт форма |
| KeyFilter | Фильтрация клавиш | [KeyFilter](https://primeng.org/keyfilter); не заменяет валидацию вставленного/полученного значения |
| Knob | Круговой индикатор/ползунок | [Knob](https://primeng.org/knob); для точного ввода обычно лучше обычное поле |
| Listbox | Выбор из списка | [Listbox](https://primeng.org/listbox); для простого списка предпочесть нативный select |
| MegaMenu | Многоуровневая навигация | [MegaMenu](https://primeng.org/megamenu); избыточен для компактной панели |
| Menu | Меню команд | [Menu](https://primeng.org/menu); проверить клавиатурное управление и фокус |
| Menubar | Горизонтальная навигация | [Menubar](https://primeng.org/menubar); адаптация к узкому экрану требует проверки |
| Message | Сообщение состояния | [Message](https://primeng.org/message); важный статус дополнительно озвучивать через live region |
| MeterGroup | Сводный индикатор измерений | [MeterGroup](https://primeng.org/metergroup); числа должны иметь текстовое объяснение |
| Motion | Движение/анимация | [Motion](https://primeng.org/motion); учитывать системную настройку уменьшения движения |
| MultiSelect | Выбор нескольких значений | [MultiSelect](https://primeng.org/multiselect); для длинных списков определить поиск и управление клавиатурой |
| OrderList | Перестановка записей | [OrderList](https://primeng.org/orderlist); проверить кнопку/клавиатурную альтернативу drag-and-drop |
| OrganizationChart | Иерархическая диаграмма | [OrganizationChart](https://primeng.org/organizationchart); сложные деревья требуют доступного альтернативного списка |
| OverlayBadge | Значок поверх элемента | [Badge](https://primeng.org/badge); счётчик должен иметь доступное текстовое имя |
| Paginator | Переход по страницам | [Paginator](https://primeng.org/paginator); согласовать страницу, размер и пустые результаты |
| Panel | Разделяемая панель | [Panel](https://primeng.org/panel); сворачивание должно быть доступно с клавиатуры |
| PanelMenu | Иерархическое меню панели | [PanelMenu](https://primeng.org/panelmenu); использовать только для реальной структуры навигации |
| Password | Пароль с подсказками | [Password](https://primeng.org/password); не хранить введённый секрет в browser storage |
| PickList | Перемещение между списками | [PickList](https://primeng.org/picklist); предусмотреть клавиатурные операции |
| Popover | Всплывающий контент | [Popover](https://primeng.org/popover); закрытие и фокус должны быть управляемыми |
| ProgressBar | Линейный прогресс | [ProgressBar](https://primeng.org/progressbar); показывать текстовое состояние и неопределённый прогресс отдельно |
| ProgressSpinner | Круговой прогресс | [ProgressSpinner](https://primeng.org/progressspinner); не использовать один бесконечный индикатор без текста |
| RadioButton | Выбор одного варианта | [RadioButton](https://primeng.org/radiobutton); группировать связанные варианты |
| Rating | Оценка звёздами | [Rating](https://primeng.org/rating); звёзды не подходят для точных числовых значений |
| Ripple | Визуальный эффект нажатия | [Ripple](https://primeng.org/ripple); декоративен и должен отключаться с уменьшением движения |
| Scroller | Виртуальная прокрутка | [Scroller](https://primeng.org/scroller); сложность доступности и динамических высот |
| ScrollPanel | Стилизация области прокрутки | [ScrollPanel](https://primeng.org/scrollpanel); сохранять нативную прокрутку и клавиатурный доступ |
| ScrollTop | Быстрый переход вверх | [ScrollTop](https://primeng.org/scrolltop); скрывать, когда действие не нужно |
| Select | Выбор одного значения | [Select](https://primeng.org/select); для малых статических списков рассмотреть нативный select |
| SelectButton | Кнопки взаимоисключающего выбора | [SelectButton](https://primeng.org/selectbutton); только для короткого набора вариантов |
| Skeleton | Заглушка загрузки | [Skeleton](https://primeng.org/skeleton); не объявлять макет содержимым |
| Slider | Диапазонный ввод | [Slider](https://primeng.org/slider); точное значение также дать числовым полем |
| SpeedDial | Плавающее меню действий | [SpeedDial](https://primeng.org/speeddial); не закрывать им основные действия |
| SplitButton | Основное действие и меню | [SplitButton](https://primeng.org/splitbutton); убедиться, что вторичные команды предсказуемы |
| Splitter | Разделение областей | [Splitter](https://primeng.org/splitter); учитывать сенсорное и клавиатурное изменение размеров |
| Stepper | Пошаговый процесс | [Stepper](https://primeng.org/stepper); не скрывать ошибки и общий прогресс |
| Steps | Индикатор этапов | [Steps](https://primeng.org/steps); сам по себе не управляет состоянием формы |
| StyleClass | Переключение CSS-класса | [StyleClass](https://primeng.org/styleclass); предпочтительнее явное состояние Angular, если оно типизируется |
| Table | Табличные данные | [Table](https://primeng.org/table); проверять семантику заголовков, сортировку и малый экран |
| Tabs | Вкладки | [Tabs](https://primeng.org/tabs); содержимое вне активной вкладки не должно терять доступное состояние |
| Tag | Короткая метка/статус | [Tag](https://primeng.org/tag); цвет не должен быть единственным сигналом |
| Terminal | Терминальный вывод | [Terminal](https://primeng.org/terminal); не подключать к привилегированной оболочке |
| Textarea | Многострочный ввод | [Textarea](https://primeng.org/textarea); ограничивать размер и не выводить секрет обратно |
| TieredMenu | Многоуровневое меню | [TieredMenu](https://primeng.org/tieredmenu); проверить управление клавиатурой и фокус |
| Timeline | Хронологический список | [Timeline](https://primeng.org/timeline); сохранять смысловой порядок в DOM |
| Toast | Всплывающие уведомления | [Toast](https://primeng.org/toast); не использовать как единственное место критичной ошибки |
| ToggleButton | Кнопка-переключатель | [ToggleButton](https://primeng.org/togglebutton); имя и состояние должны быть озвучены |
| ToggleSwitch | Переключатель состояния | [ToggleSwitch](https://primeng.org/toggleswitch); для неоднозначных действий добавить явный текст |
| Toolbar | Группа команд | [Toolbar](https://primeng.org/toolbar); не заменяет навигацию |
| Tooltip | Всплывающая подсказка | [Tooltip](https://primeng.org/tooltip); не помещать туда обязательный текст или ошибку |
| Tree | Дерево записей | [Tree](https://primeng.org/tree); оценить клавиатурную навигацию и масштабируемость |
| TreeSelect | Выбор из дерева | [TreeSelect](https://primeng.org/treeselect); дерево усложняет экранные формы |
| TreeTable | Иерархическая таблица | [TreeTable](https://primeng.org/treetable); проверить представление на узком экране и доступность |

## Headless-компоненты Angular CDK

В проекте нет собственного UI-kit на базе CDK. Доступны accessibility/key manager, bidi, clipboard, collections/selection model, dialog, drag-drop, layout/observers, listbox/menu/stepper/tree, overlay, portal, scrolling, table и text-field primitives. Они предоставляют поведение без готовой темы и внешнего вида. [Каталог CDK](https://material.angular.dev/cdk/categories). Для каждой выбранной директивы нужно отдельно проверить focus management, роли ARIA и клавиатурную модель; CDK не делает произвольную разметку автоматически доступной.

## Использование в форме AWG

Форма импорта использует PrimeNG Button, FileUpload, InputNumber, InputText и Select. Они подходят для выбора файла, ввода ID и позиции и выбора группы. Выбранный файл остаётся только в памяти браузера; проверка размера на клиенте дополняет, но не заменяет backend-проверку. Остальные компоненты перечислены для повторного применения; это инвентаризация, а не утверждение, что каждый компонент прошёл проектную проверку доступности и поведения.
