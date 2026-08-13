const MAX_RENDER_DEPTH = 8;

const RENDERERS = {
  Text(props, _children, _depth) {
    const el = document.createElement("div");
    el.className = "genui-text";
    el.textContent = props.content || "";
    return el;
  },
  Heading(props, _children, _depth) {
    const level = Math.min(Math.max(props.level || 2, 1), 4);
    const el = document.createElement(`h${level}`);
    el.className = "genui-heading";
    el.textContent = props.content || "";
    return el;
  },
  Button(props, _children, _depth) {
    const el = document.createElement("button");
    el.type = "button";
    el.className = `genui-button genui-button-${props.variant || "default"}`;
    el.textContent = props.label || "Action";
    if (props.disabled) el.disabled = true;
    if (props.action) {
      el.addEventListener("click", () => dispatchAction(props.action), { once: true });
    }
    return el;
  },
  Section(props, children, depth) {
    const el = document.createElement("section");
    el.className = "genui-section";
    if (props.title) {
      const h = document.createElement("h3");
      h.textContent = props.title;
      el.append(h);
    }
    if (props.description) {
      const p = document.createElement("p");
      p.textContent = props.description;
      el.append(p);
    }
    renderChildren(el, children, depth);
    return el;
  },
  Row(props, children, depth) {
    const el = document.createElement("div");
    el.className = `genui-row genui-gap-${props.gap || "md"}`;
    renderChildren(el, children, depth);
    return el;
  },
  Column(props, children, depth) {
    const el = document.createElement("div");
    el.className = `genui-column genui-gap-${props.gap || "md"}`;
    renderChildren(el, children, depth);
    return el;
  },
  EntityCard(props, _children, _depth) {
    const el = document.createElement("article");
    el.className = "genui-entity-card";
    const title = document.createElement("strong");
    title.textContent = props.title || "Untitled";
    el.append(title);
    if (props.subtitle) {
      const sub = document.createElement("span");
      sub.className = "genui-entity-subtitle";
      sub.textContent = props.subtitle;
      el.append(sub);
    }
    return el;
  },
  DataTable(props, _children, _depth) {
    const wrapper = document.createElement("div");
    wrapper.className = "genui-data-table";
    if (props.title) {
      const caption = document.createElement("div");
      caption.className = "genui-table-title";
      caption.textContent = props.title;
      wrapper.append(caption);
    }
    const table = document.createElement("table");
    const columns = props.columns || [];
    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    for (const col of columns) {
      const th = document.createElement("th");
      th.textContent = col.label || col.key;
      headRow.append(th);
    }
    thead.append(headRow);
    table.append(thead);
    const tbody = document.createElement("tbody");
    for (const row of (props.data || [])) {
      const tr = document.createElement("tr");
      for (const col of columns) {
        const td = document.createElement("td");
        const val = row[col.key];
        td.textContent = val == null ? "" : String(val);
        tr.append(td);
      }
      tbody.append(tr);
    }
    if (!(props.data || []).length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = columns.length || 1;
      td.textContent = props.empty_message || "No data available";
      td.className = "genui-empty";
      tr.append(td);
      tbody.append(tr);
    }
    table.append(tbody);
    wrapper.append(table);
    return wrapper;
  },
  TreeView(props, _children, _depth) {
    const ul = document.createElement("ul");
    ul.className = "genui-tree";
    for (const node of (props.nodes || [])) {
      const li = document.createElement("li");
      li.textContent = node.label || node.id;
      ul.append(li);
    }
    return ul;
  },
  Callout(props, _children, _depth) {
    const el = document.createElement("div");
    const variant = props.variant || "info";
    el.className = `genui-callout genui-callout-${variant}`;
    el.textContent = props.message || "";
    return el;
  },
  Stat(props, _children, _depth) {
    const el = document.createElement("div");
    el.className = "genui-stat";
    const label = document.createElement("span");
    label.className = "genui-stat-label";
    label.textContent = props.label || "";
    const value = document.createElement("span");
    value.className = "genui-stat-value";
    value.textContent = String(props.value ?? "");
    if (props.trend) {
      const indicator = props.trend === "up" ? "↑" : props.trend === "down" ? "↓" : "→";
      value.textContent += ` ${indicator}`;
    }
    el.append(label, value);
    return el;
  },
  StatGroup(props, children, depth) {
    const el = document.createElement("div");
    el.className = "genui-stat-group";
    el.style.gridTemplateColumns = `repeat(${props.columns || 3}, 1fr)`;
    renderChildren(el, children, depth);
    return el;
  },
};

function renderNode(node, depth) {
  if (depth > MAX_RENDER_DEPTH) {
    const el = document.createElement("div");
    el.className = "genui-depth-exceeded";
    el.textContent = "[depth limit exceeded]";
    return el;
  }
  const renderer = RENDERERS[node.component];
  if (renderer) {
    return renderer(node.props || {}, node.children || [], depth);
  }
  const el = document.createElement("div");
  el.className = "genui-unknown";
  el.textContent = `[unsupported: ${node.component}]`;
  return el;
}

function renderChildren(parent, children, depth) {
  for (const child of children || []) {
    parent.append(renderNode(child, depth + 1));
  }
}

const KNOWN_ACTIONS = new Set([
  "navigate", "refresh_data", "copy_to_clipboard",
  "open_entity", "approve_grant", "dismiss",
]);

const CONFIRM_ACTIONS = new Set(["approve_grant"]);

function dispatchAction(action) {
  if (!action || !action.name || !KNOWN_ACTIONS.has(action.name)) return;
  if (CONFIRM_ACTIONS.has(action.name)) {
    if (!window.confirm(`Confirm action: ${action.name}?`)) return;
  }
  console.log("[genui] action dispatched:", action.name, action.params);
}

export function renderGenUiDocument(container, docJson) {
  try {
    const doc = typeof docJson === "string" ? JSON.parse(docJson) : docJson;
    const fragment = document.createDocumentFragment();
    for (const node of doc.root || []) {
      fragment.append(renderNode(node, 1));
    }
    const wrapper = document.createElement("div");
    wrapper.className = "genui-document";
    wrapper.append(fragment);
    container.append(wrapper);
  } catch (e) {
    const err = document.createElement("div");
    err.className = "genui-error";
    err.textContent = "[GenUI render error]";
    container.append(err);
  }
}
