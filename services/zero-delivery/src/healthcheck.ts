const port = process.env.ZERO_DELIVERY_PORT ?? "2525";
const response = await fetch(`http://127.0.0.1:${port}/health`);

if (!response.ok) {
  process.exit(1);
}
