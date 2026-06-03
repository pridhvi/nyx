declare module "dagre" {
  import type { Graph } from "@dagrejs/graphlib";

  export function layout(graph: Graph): void;

  const dagre: {
    layout: typeof layout;
  };

  export default dagre;
}
