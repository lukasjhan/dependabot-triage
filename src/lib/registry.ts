export type Manifest = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  repository?: string | { url: string; directory?: string };
  pnpm?: { overrides?: Record<string, string> };
};

export type Packument = {
  "dist-tags": { latest: string };
  time: Record<string, string>;
  versions: Record<string, Manifest>;
  repository?: Manifest["repository"];
};

const cache = new Map<string, Promise<Packument>>();

export function packument(name: string): Promise<Packument> {
  if (!cache.has(name)) {
    cache.set(
      name,
      fetch(`https://registry.npmjs.org/${name.replace("/", "%2F")}`).then((r) => {
        if (!r.ok) throw new Error(`registry ${name} -> ${r.status}`);
        return r.json() as Promise<Packument>;
      }),
    );
  }
  return cache.get(name)!;
}
