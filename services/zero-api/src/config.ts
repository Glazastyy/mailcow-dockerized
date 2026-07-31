export type ZeroApiConfig = {
  host: string;
  port: number;
  zeroAccessRequired: true;
  databaseName: string;
  databaseUser: string;
  redisConfigured: boolean;
  timezone: string;
};

export function readConfig(env: Record<string, string | undefined>): ZeroApiConfig {
  const zeroAccessRequired = env.ZERO_ACCESS_REQUIRED ?? "y";

  if (zeroAccessRequired !== "y") {
    throw new Error("ZERO_ACCESS_REQUIRED must be y");
  }

  const port = Number(env.ZERO_API_PORT ?? "8080");

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("ZERO_API_PORT must be a valid TCP port");
  }

  return {
    host: env.ZERO_API_HOST ?? "0.0.0.0",
    port,
    zeroAccessRequired: true,
    databaseName: env.DBNAME ?? "",
    databaseUser: env.DBUSER ?? "",
    redisConfigured: Boolean(env.REDISPASS),
    timezone: env.TZ ?? "UTC"
  };
}
