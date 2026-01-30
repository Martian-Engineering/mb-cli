import type { CommandContext } from "../cli/context";
import {
  listSensitiveEntries,
  loadSensitiveStore,
  removeSensitiveEntry,
  resolveProfileName,
  saveSensitiveStore,
  upsertSensitiveEntry,
} from "../lib/config";
import { printInfo, printJson } from "../lib/output";

export function registerSecretCommands(ctx: CommandContext): void {
  const { program, globals } = ctx;

  const secrets = program.command("secrets").description("Manage sensitive facts");

  secrets
    .command("add")
    .description("Add a sensitive fact")
    .requiredOption("--label <label>", "Label")
    .requiredOption("--pattern <pattern>", "Pattern or literal")
    .option("--regex", "Treat pattern as regex")
    .option("--severity <level>", "low|medium|high", "high")
    .action((cmd) => {
      const opts = globals();
      const profileName = resolveProfileName(opts.profile);
      const store = loadSensitiveStore();
      const updated = upsertSensitiveEntry(store, profileName, {
        label: cmd.label,
        pattern: cmd.pattern,
        regex: !!cmd.regex,
        severity: cmd.severity,
      });
      saveSensitiveStore(updated);

      if (opts.json) {
        printJson({ profile: profileName, added: cmd.label });
        return;
      }
      printInfo(`Added sensitive fact '${cmd.label}' for profile '${profileName}'.`, opts);
    });

  secrets
    .command("list")
    .description("List sensitive facts")
    .option("--reveal", "Show patterns")
    .action((cmd) => {
      const opts = globals();
      const profileName = resolveProfileName(opts.profile);
      const store = loadSensitiveStore();
      const entries = listSensitiveEntries(store, profileName);

      if (opts.json) {
        printJson({ profile: profileName, entries });
        return;
      }

      if (entries.length === 0) {
        printInfo("No sensitive facts configured.", opts);
        return;
      }

      for (const entry of entries) {
        const pattern = cmd.reveal ? entry.pattern : "[redacted]";
        printInfo(`${entry.label}: ${pattern}`, opts);
      }
    });

  secrets
    .command("remove")
    .description("Remove a sensitive fact")
    .argument("<label>", "Label to remove")
    .action((label) => {
      const opts = globals();
      const profileName = resolveProfileName(opts.profile);
      const store = loadSensitiveStore();
      const updated = removeSensitiveEntry(store, profileName, label);
      saveSensitiveStore(updated);

      if (opts.json) {
        printJson({ profile: profileName, removed: label });
        return;
      }
      printInfo(`Removed sensitive fact '${label}'.`, opts);
    });

  secrets
    .command("import")
    .description("Stub: auto-import sensitive facts (phase 2)")
    .option("--source <source>", "Source to import (qmd)", "qmd")
    .action((cmd) => {
      const opts = globals();
      const profileName = resolveProfileName(opts.profile);
      const note = `Sensitive fact auto-import is a phase 2 stub. Source=${cmd.source}. Use 'mb secrets add' for now.`;
      if (opts.json) {
        printJson({ profile: profileName, stub: true, message: note });
        return;
      }
      printInfo(note, opts);
    });
}
