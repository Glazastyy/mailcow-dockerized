import { appendFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

export type RecipientRouteKind = "alias" | "catch_all";

export type RecipientRoute = {
  id?: string;
  address: string;
  recipients: string[];
  kind: RecipientRouteKind;
  created?: string;
};

export type RecipientRouteInput = Omit<RecipientRoute, "id" | "created">;

export type RecipientDirectory = {
  save(route: RecipientRouteInput): Promise<RecipientRoute>;
  resolve(address: string): Promise<string[] | undefined>;
};

const routeKinds = ["alias", "catch_all"] as const;

function normalizeAddress(address: string) {
  return address.trim().toLowerCase();
}

function normalizeRecipients(recipients: string[]) {
  return Array.from(new Set(recipients.map((recipient) => normalizeAddress(recipient)).filter((recipient) => recipient.length > 0)));
}

function createRecord(route: RecipientRouteInput): RecipientRoute {
  return {
    ...route,
    id: crypto.randomUUID(),
    address: normalizeAddress(route.address),
    recipients: normalizeRecipients(route.recipients),
    created: new Date().toISOString()
  };
}

function isRecipientRoute(value: unknown): value is RecipientRoute {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const record = value as Record<string, unknown>;

  return (
    typeof record.id === "string" &&
    typeof record.address === "string" &&
    Array.isArray(record.recipients) &&
    record.recipients.every((recipient) => typeof recipient === "string" && recipient.length > 0) &&
    routeKinds.includes(record.kind as RecipientRouteKind) &&
    typeof record.created === "string"
  );
}

function resolveFromRoutes(routes: RecipientRoute[], address: string) {
  const normalizedAddress = normalizeAddress(address);
  const exact = routes.findLast((route) => route.address === normalizedAddress);

  if (exact) {
    return exact.recipients;
  }

  const domain = normalizedAddress.split("@")[1];

  if (domain) {
    const catchAll = routes.findLast((route) => route.address === `*@${domain}` && route.kind === "catch_all");

    if (catchAll) {
      return catchAll.recipients;
    }
  }

  return [normalizedAddress];
}

export function createMemoryRecipientDirectory(routes: RecipientRoute[] = []): RecipientDirectory {
  return {
    async save(route) {
      const record = createRecord(route);
      routes.push(record);
      return record;
    },
    async resolve(address) {
      return resolveFromRoutes(routes, address);
    }
  };
}

export function createFileRecipientDirectory(root: string): RecipientDirectory {
  const directory = join(root, "recipients");
  const recordsPath = join(directory, "routes.jsonl");

  return {
    async save(route) {
      const record = createRecord(route);
      await mkdir(directory, { recursive: true });
      await appendFile(recordsPath, `${JSON.stringify(record)}\n`, { encoding: "utf8" });
      return record;
    },
    async resolve(address) {
      return resolveFromRoutes(await readAllRecords(recordsPath), address);
    }
  };
}

async function readAllRecords(path: string) {
  let data: string;

  try {
    data = await readFile(path, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return [];
    }

    throw error;
  }

  const records: RecipientRoute[] = [];

  for (const line of data.trimEnd().split("\n")) {
    if (!line) {
      continue;
    }

    const parsed = JSON.parse(line) as unknown;

    if (isRecipientRoute(parsed)) {
      records.push(parsed);
    }
  }

  return records;
}

export function validateRecipientRoutePayload(payload: Record<string, unknown>): { ok: true; route: RecipientRouteInput } | { ok: false; error: string } {
  if (typeof payload.address !== "string" || payload.address.trim().length === 0) {
    return { ok: false, error: "missing_address" };
  }

  if (!Array.isArray(payload.recipients) || payload.recipients.length === 0) {
    return { ok: false, error: "missing_recipients" };
  }

  const kind = payload.kind === undefined ? "alias" : String(payload.kind);

  if (!routeKinds.includes(kind as RecipientRouteKind)) {
    return { ok: false, error: "invalid_kind" };
  }

  const recipients = normalizeRecipients(payload.recipients.filter((recipient): recipient is string => typeof recipient === "string"));

  if (recipients.length === 0) {
    return { ok: false, error: "missing_recipients" };
  }

  const address = normalizeAddress(payload.address);

  if (kind === "catch_all" && !/^\*@[^@\s]+\.[^@\s]+$/.test(address)) {
    return { ok: false, error: "invalid_catch_all_address" };
  }

  if (kind === "alias" && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(address)) {
    return { ok: false, error: "invalid_address" };
  }

  return {
    ok: true,
    route: {
      address,
      recipients,
      kind: kind as RecipientRouteKind
    }
  };
}
