/** Each implemented page supplies its navigation label, heading, and routing metadata. */
export const pages = [
  {
    path: "groups",
    label: "Группы подключений",
    description: "Группы и порядок выхода через настроенные подключения.",
  },
  {
    path: "domain-lists",
    label: "Доменные списки",
    description: "Маски доменов и привязки списков к группам подключений.",
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

/** Additional sections are loaded on first navigation, keeping the startup bundle small. */
export const featurePages = [
  {
    path: "country-map",
    label: "Маршруты по странам",
    loadComponent: () => import("./geo/geo.component").then((m) => m.GeoScreen),
  },
  {
    path: "traffic",
    label: "Журнал трафика",
    loadComponent: () =>
      import("./traffic/traffic.component").then((m) => m.TrafficScreen),
  },
  {
    path: "quality",
    label: "Качество связи",
    loadComponent: () =>
      import("./quality/quality.component").then((m) => m.QualityScreen),
  },
  {
    path: "dns",
    label: "DNS",
    loadComponent: () => import("./dns/dns.component").then((m) => m.DnsScreen),
  },
] as const;

/** Ordered links displayed in the panel navigation. */
export const navigationPages = [...pages, ...featurePages] as const;
