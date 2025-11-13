import type { SDK } from "caido:plugin";
import { init as registerRetireApi, type RetireAPI } from "./script";

export type API = RetireAPI;

export function init(sdk: SDK<API>): void {
  registerRetireApi(sdk);
}
