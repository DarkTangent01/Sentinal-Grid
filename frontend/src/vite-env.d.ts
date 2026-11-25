/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Build-time product: "grid" or "nms" builds that product alone (vite --mode grid|nms); empty = both. */
  readonly VITE_PRODUCT?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
