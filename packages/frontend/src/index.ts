import type { FrontendSDK } from "./types";
import { init as registerRetirePanel } from "./script";
import "./styles/index.css";
import "./styles/style.css";


export const init = (sdk: FrontendSDK): void => {
  registerRetirePanel(sdk);
};
