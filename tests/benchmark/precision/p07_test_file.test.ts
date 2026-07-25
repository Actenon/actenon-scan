// p07: __tests__/*.test.ts with fs.rm — must produce 0 findings
// (TS test files are excluded by default)
import * as fs from "fs";
import * as path from "path";

describe("cleanup", () => {
  const testDir = path.join(__dirname, "tmp");

  beforeEach(() => {
    fs.mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it("writes a file", () => {
    fs.writeFileSync(path.join(testDir, "test.txt"), "hello");
  });
});
