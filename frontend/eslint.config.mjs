import js from "@eslint/js";
import ts from "typescript-eslint";
import angular from "angular-eslint";

export default [
  { ignores: ["src/api/generated/**"] },
  ...ts.config({
    files: ["src/**/*.ts"],
    extends: [
      js.configs.recommended,
      ...ts.configs.recommended,
      ...angular.configs.tsRecommended,
    ],
    processor: angular.processInlineTemplates,
  }),
  {
    files: ["src/**/*.html"],
    ...angular.configs.templateRecommended.at(-1),
    languageOptions: { parser: angular.templateParser },
    plugins: { "@angular-eslint/template": angular.templatePlugin },
    rules: {
      ...angular.configs.templateRecommended.at(-1).rules,
      ...angular.configs.templateAccessibility.at(-1).rules,
    },
  },
];
