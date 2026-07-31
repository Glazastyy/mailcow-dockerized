import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const schema = readFileSync("data/web/inc/init_db.inc.php", "utf8");

function tableBlock(table: string) {
  const start = schema.indexOf(`"${table}" => array(`);
  expect(start).toBeGreaterThanOrEqual(0);

  const next = schema.indexOf(`\n      "`, start + 1);
  return schema.slice(start, next === -1 ? undefined : next);
}

describe("zero-access database schema", () => {
  test("bumps the schema version for zero-access tables", () => {
    expect(schema).toContain('$db_version = "31072026_0001"');
  });

  test("declares all zero-access tables", () => {
    for (const table of [
      "zero_user_keys",
      "zero_recipient_keys",
      "zero_messages",
      "zero_attachments",
      "zero_key_events",
      "zero_recovery"
    ]) {
      expect(schema).toContain(`"${table}" => array(`);
    }
  });

  test("stores user private keys only as encrypted payloads", () => {
    const block = tableBlock("zero_user_keys");

    expect(block).toContain('"encrypted_private_key" => "LONGTEXT NOT NULL"');
    expect(block).toContain('"public_key_armored" => "MEDIUMTEXT NOT NULL"');
    expect(block).not.toContain('"private_key" =>');
    expect(block).not.toContain('"secret_key" =>');
  });

  test("stores message and attachment bodies only as encrypted blob references", () => {
    const messageBlock = tableBlock("zero_messages");
    const attachmentBlock = tableBlock("zero_attachments");

    expect(messageBlock).toContain('"encrypted_blob_ref" => "VARCHAR(512) NOT NULL"');
    expect(messageBlock).toContain('"encrypted_subject" => "TEXT"');
    expect(messageBlock).not.toContain('"body" =>');
    expect(messageBlock).not.toContain('"msg" =>');
    expect(attachmentBlock).toContain('"encrypted_blob_ref" => "VARCHAR(512) NOT NULL"');
    expect(attachmentBlock).toContain('"encrypted_name" => "TEXT"');
  });
});
