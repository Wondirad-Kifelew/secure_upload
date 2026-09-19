export function createFakeScanner({ clean = true, findings = [] } = {}) {
  return {
    name: "Fake Scanner",
    async scan(_buffer, _meta) {
      return { clean, findings };
    },
  };
}

export const FakeScanner = createFakeScanner();