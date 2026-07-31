export type ZeroDeliveryConfig = {
  host: string;
  port: number;
  zeroAccessRequired: true;
};

export function readConfig(env: Record<string, string | undefined>): ZeroDeliveryConfig {
  if ((env.ZERO_ACCESS_REQUIRED ?? "y") !== "y") {
    throw new Error("ZERO_ACCESS_REQUIRED must be y");
  }

  const port = Number(env.ZERO_DELIVERY_PORT ?? "2525");

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("ZERO_DELIVERY_PORT must be a valid TCP port");
  }

  return {
    host: env.ZERO_DELIVERY_HOST ?? "0.0.0.0",
    port,
    zeroAccessRequired: true
  };
}
