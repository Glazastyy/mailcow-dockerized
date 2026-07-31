import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

export type BlobStore = {
  write(data: Uint8Array): Promise<{ id: string; sha256: string; size: number }>;
  read(id: string): Promise<Uint8Array | undefined>;
};

async function sha256(data: Uint8Array) {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function assertBlobId(id: string) {
  if (!/^[a-f0-9-]{36}$/.test(id)) {
    throw new Error("Invalid blob id");
  }
}

export function createMemoryBlobStore(blobs = new Map<string, Uint8Array>()): BlobStore {
  return {
    async write(data) {
      const id = crypto.randomUUID();
      const hash = await sha256(data);
      blobs.set(id, data);
      return { id, sha256: hash, size: data.byteLength };
    },
    async read(id) {
      return blobs.get(id);
    }
  };
}

export function createFileBlobStore(root: string): BlobStore {
  return {
    async write(data) {
      const id = crypto.randomUUID();
      const hash = await sha256(data);
      await mkdir(root, { recursive: true });
      await writeFile(join(root, id), data);
      return { id, sha256: hash, size: data.byteLength };
    },
    async read(id) {
      assertBlobId(id);

      try {
        return await readFile(join(root, id));
      } catch (error) {
        if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
          return undefined;
        }

        throw error;
      }
    }
  };
}
