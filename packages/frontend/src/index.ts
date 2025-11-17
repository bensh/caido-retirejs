import { init as registerRetirePanel } from "./script";
import "./styles/index.css";
import "./styles/style.css";
import type { FrontendSDK } from "./types";

export const init = (sdk: FrontendSDK): void => {
  registerRetirePanel(sdk);
};
