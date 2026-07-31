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
    expect(schema).toContain('$db_version = "31072026_0002"');
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

  test("tracks password re-encryption and destructive reset states for user keys", () => {
    const keyBlock = tableBlock("zero_user_keys");
    const eventBlock = tableBlock("zero_key_events");

    expect(keyBlock).toContain('"rotation_mode" => "ENUM(\'initial\',\'password_reencrypt\',\'password_reset\',\'recovery_reencrypt\',\'key_rotation\') NOT NULL DEFAULT \'initial\'"');
    expect(keyBlock).toContain('"previous_key_id" => "BIGINT DEFAULT NULL"');
    expect(keyBlock).toContain('"previous_key_id" => array("previous_key_id")');
    expect(keyBlock).toContain('"fk_zero_user_keys_previous_key"');
    expect(eventBlock).toContain("password_reencrypted");
    expect(eventBlock).toContain("password_reset");
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
