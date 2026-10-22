import { Fragment, isValidElement } from "react";
import { tr } from "./core.js";

/**
 * `tr()` for sentences that embed markup: `trRich("key", { n: <strong>{n}</strong>, count: n })`
 * returns the translated sentence with each `{name}` placeholder replaced by the matching React
 * element. Plain values (strings, numbers, `count` for plural forms) are substituted as text.
 */
export function trRich(key, vars = {}) {
  const plain = {};
  const nodes = {};
  for (const [name, value] of Object.entries(vars)) {
    if (isValidElement(value)) nodes[name] = value;
    else plain[name] = value;
  }
  return tr(key, plain)
    .split(/(\{\w+\})/)
    .map((part, i) => {
      const match = /^\{(\w+)\}$/.exec(part);
      return <Fragment key={i}>{match && match[1] in nodes ? nodes[match[1]] : part}</Fragment>;
    });
}
