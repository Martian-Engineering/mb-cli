export type OutputOptions = {
  json?: boolean;
  quiet?: boolean;
};

export function printJson(data: unknown): void {
  const payload = {
    schema_version: 1,
    data,
  };
  console.log(JSON.stringify(payload, null, 2));
}

export function printError(message: string, opts: OutputOptions = {}): void {
  if (opts.json) {
    printJson({ error: { message } });
    return;
  }
  if (!opts.quiet) {
    console.error(message);
  }
}

export function printInfo(message: string, opts: OutputOptions = {}): void {
  if (opts.json) {
    printJson({ message });
    return;
  }
  if (!opts.quiet) {
    console.log(message);
  }
}
