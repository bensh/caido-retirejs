import { type Caido as CaidoSDK } from "@caido/sdk-frontend";
import { type API as BackendAPI } from "backend";

type BackendEndpointMap = Record<string, (...args: unknown[]) => unknown>;

export type FrontendSDK = CaidoSDK<BackendAPI & BackendEndpointMap>;
