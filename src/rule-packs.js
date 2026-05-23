import { scanCommon } from "./rules/common.js";
import { scanNode } from "./rules/node.js";
import { scanSpring } from "./rules/spring.js";

export const rulePacks = [
  {
    id: "@stacklens/common",
    name: "Common",
    ecosystem: "common",
    scan: (context) => ({ detected: true, findings: scanCommon(context) }),
    stacks: () => []
  },
  {
    id: "@stacklens/spring",
    name: "Spring Boot",
    ecosystem: "spring",
    scan: scanSpring,
    stacks: (result) => (result.detected ? ["Spring Boot"] : [])
  },
  {
    id: "@stacklens/node",
    name: "Node.js",
    ecosystem: "node",
    scan: scanNode,
    stacks: (result) => {
      if (!result.detected) return [];
      return ["Node.js", ...(result.frameworks ?? [])];
    }
  }
];

export function runRulePacks(context, packs = rulePacks) {
  return packs.map((pack) => ({
    pack,
    result: pack.scan(context)
  }));
}

export function listRulePackSummaries(packResults) {
  return packResults.map(({ pack, result }) => ({
    id: pack.id,
    name: pack.name,
    ecosystem: pack.ecosystem,
    detected: Boolean(result.detected)
  }));
}

export function detectStacks(packResults) {
  const stacks = packResults.flatMap(({ pack, result }) => pack.stacks(result));
  return Array.from(new Set(stacks));
}

export function getPackResult(packResults, ecosystem) {
  return packResults.find(({ pack }) => pack.ecosystem === ecosystem)?.result;
}
