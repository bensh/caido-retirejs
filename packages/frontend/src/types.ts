import { type Caido as CaidoSDK } from "@caido/sdk-frontend";
import { type API as BackendAPI } from "backend";

export type FrontendSDK = CaidoSDK<BackendAPI>;
