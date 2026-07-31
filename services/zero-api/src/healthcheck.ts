const port = process.env.ZERO_API_PORT ?? "8080";
const response = await fetch(`http://127.0.0.1:${port}/health`);

if (!response.ok) {
  process.exit(1);
}
