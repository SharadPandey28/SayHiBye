import pino from "pino";
import { config } from "./index.js";

export const logger = pino({
  level: config.isDev ? "debug" : "info",
  transport: config.isDev
    ? { target: "pino-pretty", options: { colorize: true, translateTime: "HH:MM:ss" } }
    : undefined,
  base: { service: "dh-secure-chat" },
});
