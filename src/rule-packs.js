import { scanCommon } from "./rules/common.js";
import { scanNode } from "./rules/node.js";
import { scanQuarkus } from "./rules/quarkus.js";
import { scanReact } from "./rules/react.js";
import { scanSpring } from "./rules/spring.js";
import { scanVue } from "./rules/vue.js";

export const rulePacks = [
  {
    id: "@stacklens/common",
    name: "Common",
    ecosystem: "common",
    scan: scanCommon,
    stacks: (result) => [
      ...(result.hasOpenShift ? ["OpenShift"] : []),
      ...(result.hasArgoCd ? ["Argo CD"] : []),
      ...(result.hasHelm ? ["Helm"] : []),
      ...(result.hasKustomize ? ["Kustomize"] : [])
    ]
  },
  {
    id: "@stacklens/spring",
    name: "Spring Boot",
    ecosystem: "spring",
    scan: scanSpring,
    stacks: (result) => (result.detected ? ["Spring Boot"] : [])
  },
  {
    id: "@stacklens/quarkus",
    name: "Quarkus",
    ecosystem: "quarkus",
    scan: scanQuarkus,
    stacks: (result) => {
      if (!result.detected) return [];
      return [
        "Quarkus",
        ...(result.usesCamel ? ["Apache Camel"] : []),
        ...(result.usesArtemis ? ["Apache ActiveMQ Artemis"] : []),
        ...(result.hasOpenShift ? ["OpenShift"] : []),
        ...(result.hasArgoCd ? ["Argo CD"] : [])
      ];
    }
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
  },
  {
    id: "@stacklens/react",
    name: "React",
    ecosystem: "react",
    scan: scanReact,
    stacks: (result) => (result.detected ? ["React"] : [])
  },
  {
    id: "@stacklens/vue",
    name: "Vue",
    ecosystem: "vue",
    scan: scanVue,
    stacks: (result) => (result.detected ? ["Vue"] : [])
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
