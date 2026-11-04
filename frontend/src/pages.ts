/** Each implemented page supplies its navigation label, heading, and routing metadata. */
export const pages = [
  {
    path: "groups-and-rules",
    label: "Группы и правила",
    description:
      "Выходы групп и привязки доменных списков по конфигурации шлюза.",
  },
  {
    path: "connections",
    label: "Подключения",
    description:
      "Выходы шлюза, их группы и доступность по снимку конфигурации.",
  },
] as const;

/** A route supplies one of the navigation entries declared by the application. */
export type Page = (typeof pages)[number];
