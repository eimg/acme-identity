import { useMemo, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { hasPermission } from "../../src/permissions";
import type {
  IdentityMeta,
  Principal,
  Role,
  ServiceToken,
  User,
} from "../../src/types";
import { api, formatTime } from "./api";

type Tab = "users" | "roles" | "tokens" | "account";

const tabDetails: Record<Tab, { label: string; short: string; title: string; description: string }> = {
  users: {
    label: "People",
    short: "Pe",
    title: "People",
    description: "Human accounts and the roles they carry across the Acme suite.",
  },
  roles: {
    label: "Access roles",
    short: "Ro",
    title: "Access roles",
    description: "Reusable capability sets for people and machine principals.",
  },
  tokens: {
    label: "Service tokens",
    short: "To",
    title: "Service tokens",
    description: "Scoped credentials for trusted service-to-service connections.",
  },
  account: {
    label: "My account",
    short: "Me",
    title: "My account",
    description: "Your resolved principal and local password settings.",
  },
};

interface SessionResponse {
  principal: Principal;
  user: User | null;
}

const metaQuery = { queryKey: ["meta"], queryFn: () => api<IdentityMeta>("/api/meta") };

export function App() {
  const queryClient = useQueryClient();
  const meta = useQuery(metaQuery);
  const session = useQuery({
    queryKey: ["session"],
    queryFn: async () => {
      try {
        return await api<SessionResponse>("/api/session");
      } catch {
        return null;
      }
    },
  });
  const [tab, setTab] = useState<Tab>(() => {
    const requested = new URLSearchParams(location.search).get("tab");
    return requested && requested in tabDetails ? requested as Tab : "users";
  });
  const [toast, setToast] = useState("");
  const [createdToken, setCreatedToken] = useState<string | null>(null);

  const showToast = (message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 2_800);
  };

  const principal = session.data?.principal;
  const signedIn = Boolean(principal);
  const isOff = meta.data?.authMode === "off";
  // Gate on the permission, not the role slug, so custom roles work unchanged.
  const canManage = Boolean(principal && hasPermission(principal, "identity.admin"));

  const signOut = useMutation({
    mutationFn: () => api<{ signedOut: boolean }>("/api/session", { method: "DELETE" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["session"] });
      showToast("Signed out");
    },
  });

  if (meta.isLoading || session.isLoading) {
    return (
      <div className="boot">
        <p>Opening identity…</p>
      </div>
    );
  }

  if (!isOff && !signedIn) {
    return (
      <LoginScreen
        onSuccess={async () => {
          await queryClient.invalidateQueries({ queryKey: ["session"] });
        }}
      />
    );
  }

  const activeTab = tabDetails[tab];

  return (
    <div className="app-frame">
      <aside className="sidebar">
        <div className="brand">
          <div className="mark" aria-hidden><span>AI</span></div>
          <div>
            <strong>Acme Identity</strong>
            <span>Suite access</span>
          </div>
        </div>

        <nav className="side-nav" aria-label="Identity sections">
          {(["users", "roles", "tokens", "account"] as Tab[]).map((item) => (
            <button
              key={item}
              type="button"
              className={tab === item ? "side-link active" : "side-link"}
              aria-current={tab === item ? "page" : undefined}
              onClick={() => setTab(item)}
            >
              <span className="nav-monogram" aria-hidden>{tabDetails[item].short}</span>
              <span>{tabDetails[item].label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-session">
          <div className="session-avatar" aria-hidden>
            {(principal?.displayName ?? "A").slice(0, 1).toUpperCase()}
          </div>
          <div className="session-copy">
            <strong>{principal?.displayName ?? "Admin"}</strong>
            <span>{principal?.roles.join(", ") || "development"}</span>
          </div>
          {!isOff && (
            <button type="button" className="text-button" onClick={() => signOut.mutate()}>
              Sign out
            </button>
          )}
        </div>
      </aside>

      <div className="workspace">
        <header className="mobile-header">
          <div className="brand compact">
            <div className="mark" aria-hidden><span>AI</span></div>
            <strong>Acme Identity</strong>
          </div>
          <span className={`mode-pill mode-${meta.data?.authMode ?? "local"}`}>
            {meta.data?.authMode}
          </span>
        </header>

        <main className="content">
          <div className="page-heading">
            <div>
              <span className="eyebrow">Identity console</span>
              <h1>{activeTab.title}</h1>
              <p>{activeTab.description}</p>
            </div>
            <span className={`mode-pill mode-${meta.data?.authMode ?? "local"}`}>
              {meta.data?.authMode === "off" ? "Development mode" : "Local auth"}
            </span>
          </div>

          {isOff && (
            <div className="notice" role="note">
              <span className="notice-mark" aria-hidden>i</span>
              <p>
                <strong>Authentication is bypassed for local testing.</strong>
                All requests resolve as the development admin. Use <code>ACME_AUTH_MODE=local</code>
                when testing sign-in and role enforcement.
              </p>
            </div>
          )}

          <div className="page-body">
        {tab === "account" ? (
          <AccountPanel principal={principal} onToast={showToast} />
        ) : !canManage ? (
          <p className="muted">
            Managing identity needs the <code>identity.admin</code> permission.
          </p>
        ) : tab === "users" ? (
          <UsersPanel onToast={showToast} />
        ) : tab === "roles" ? (
          <RolesPanel onToast={showToast} />
        ) : (
          <TokensPanel
            createdToken={createdToken}
            onCreatedToken={setCreatedToken}
            onToast={showToast}
          />
        )}
          </div>
        </main>
      </div>

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

function LoginScreen({ onSuccess }: { onSuccess: () => Promise<void> }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [error, setError] = useState("");
  const login = useMutation({
    mutationFn: () =>
      api("/api/session", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      }),
    onSuccess: async () => {
      setError("");
      await onSuccess();
    },
    onError: (err: Error) => setError(err.message),
  });

  return (
    <div className="login-screen">
      <form
        className="login-card"
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          login.mutate();
        }}
      >
        <div className="brand large">
          <div className="mark" aria-hidden />
          <div>
            <strong>Acme Identity</strong>
            <span>Sign in to manage users and roles</span>
          </div>
        </div>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        {error && <p className="error">{error}</p>}
        <button className="button primary" type="submit" disabled={login.isPending}>
          {login.isPending ? "Signing in…" : "Sign in"}
        </button>
        <p className="hint">Seeded: admin / operator / member / viewer (password = username)</p>
      </form>
    </div>
  );
}

function UsersPanel({ onToast }: { onToast: (message: string) => void }) {
  const queryClient = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<User[]>("/api/users") });
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => api<Role[]>("/api/roles") });
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [roleSlugs, setRoleSlugs] = useState<string[]>(["member"]);
  const [search, setSearch] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [editingUserId, setEditingUserId] = useState<number | null>(null);

  const visibleUsers = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return users.data ?? [];
    return (users.data ?? []).filter((user) =>
      [user.displayName, user.username, user.email, ...user.roleSlugs]
        .some((value) => value.toLowerCase().includes(needle)),
    );
  }, [search, users.data]);

  const create = useMutation({
    mutationFn: () =>
      api<User>("/api/users", {
        method: "POST",
        body: JSON.stringify({ username, displayName, email, password, roleSlugs }),
      }),
    onSuccess: async () => {
      setUsername("");
      setDisplayName("");
      setEmail("");
      setPassword("");
      setRoleSlugs(["member"]);
      setShowCreate(false);
      await queryClient.invalidateQueries({ queryKey: ["users"] });
      onToast("User created");
    },
    onError: (error: Error) => onToast(error.message),
  });

  const patchRoles = useMutation({
    mutationFn: ({ id, next }: { id: number; next: string[] }) =>
      api<User>(`/api/users/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ roleSlugs: next }),
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["users"] });
      onToast("Roles updated");
    },
    onError: (error: Error) => onToast(error.message),
  });

  const toggleActive = useMutation({
    mutationFn: (user: User) =>
      api<User>(`/api/users/${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({ active: !user.active }),
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["users"] });
      onToast("User updated");
    },
    onError: (error: Error) => onToast(error.message),
  });

  const remove = useMutation({
    mutationFn: (id: number) => api<void>(`/api/users/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["users"] });
      onToast("User deleted");
    },
    onError: (error: Error) => onToast(error.message),
  });

  const revokeSessions = useMutation({
    mutationFn: (id: number) =>
      api<{ revoked: number }>(`/api/users/${id}/sessions`, { method: "DELETE" }),
    onSuccess: (result) => onToast(`Revoked ${result.revoked} session(s)`),
    onError: (error: Error) => onToast(error.message),
  });

  return (
    <div className="resource-view">
      <div className="resource-toolbar">
        <label className="search-field">
          <span className="sr-only">Search people</span>
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search people, email, or role…"
          />
        </label>
        <div className="toolbar-meta">
          <span>{users.data?.length ?? 0} people</span>
          <button type="button" className="button primary" onClick={() => setShowCreate((open) => !open)}>
            {showCreate ? "Close" : "Add person"}
          </button>
        </div>
      </div>

      {showCreate && (
        <section className="editor-panel" aria-label="Add person">
          <div className="section-heading">
            <div>
              <span className="eyebrow">New account</span>
              <h2>Add a person</h2>
              <p>Create credentials, then assign one or more access roles.</p>
            </div>
          </div>
        <form
          className="form-grid"
          onSubmit={(event) => {
            event.preventDefault();
            create.mutate();
          }}
        >
          <label>
            Username
            <input value={username} onChange={(e) => setUsername(e.target.value)} required />
          </label>
          <label>
            Display name
            <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} required />
          </label>
          <label>
            Email
            <input value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label>
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            required
          />
          </label>
          <fieldset className="form-span">
            <legend>Roles</legend>
            <div className="choice-grid compact">
              {(roles.data ?? []).map((role) => {
                const on = roleSlugs.includes(role.slug);
                return (
                  <button
                    key={role.slug}
                    type="button"
                    className={on ? "choice on" : "choice"}
                    aria-pressed={on}
                    onClick={() =>
                      setRoleSlugs((current) =>
                        on ? current.filter((slug) => slug !== role.slug) : [...current, role.slug],
                      )
                    }
                  >
                    <strong>{role.name}</strong>
                    <span>{role.slug}</span>
                  </button>
                );
              })}
            </div>
          </fieldset>
          <div className="form-actions form-span">
            <button type="button" className="button" onClick={() => setShowCreate(false)}>Cancel</button>
            <button className="button primary" type="submit" disabled={create.isPending || !roleSlugs.length}>
            Create user
            </button>
          </div>
        </form>
        </section>
      )}

      <section className="list-panel">
        <div className="list-header user-grid">
          <span>Person</span>
          <span>Access</span>
          <span>Status</span>
          <span className="align-right">Actions</span>
        </div>
        <div className="data-list">
          {visibleUsers.map((user) => {
            const editing = editingUserId === user.id;
            return (
              <article key={user.id} className={editing ? "data-item expanded" : "data-item"}>
                <div className="data-row user-grid">
                  <div className="person-cell">
                    <span className="person-avatar" aria-hidden>{initials(user.displayName)}</span>
                    <span>
                      <strong>{user.displayName}</strong>
                      <small>{user.email || `@${user.username}`}</small>
                    </span>
                  </div>
                  <div className="tag-list">
                    {user.roleSlugs.map((slug) => <span key={slug} className="tag">{slug}</span>)}
                  </div>
                  <span className={user.active ? "status active" : "status inactive"}>
                    {user.active ? "Active" : "Inactive"}
                  </span>
                  <div className="row-actions align-right">
                    <button
                      type="button"
                      className="button small"
                      onClick={() => setEditingUserId(editing ? null : user.id)}
                    >
                      {editing ? "Done" : "Edit access"}
                    </button>
                    <button type="button" className="button small quiet" onClick={() => toggleActive.mutate(user)}>
                      {user.active ? "Disable" : "Enable"}
                    </button>
                  </div>
                </div>
                {editing && (
                  <div className="inline-editor">
                    <div>
                      <h3>Access roles</h3>
                      <p>Changes apply immediately across the suite.</p>
                    </div>
                    <div className="choice-grid compact">
                      {(roles.data ?? []).map((role) => {
                        const on = user.roleSlugs.includes(role.slug);
                        return (
                          <button
                            key={role.slug}
                            type="button"
                            className={on ? "choice on" : "choice"}
                            aria-pressed={on}
                            onClick={() => {
                              const next = on
                                ? user.roleSlugs.filter((slug) => slug !== role.slug)
                                : [...user.roleSlugs, role.slug];
                              if (!next.length) return onToast("At least one role is required");
                              patchRoles.mutate({ id: user.id, next });
                            }}
                          >
                            <strong>{role.name}</strong>
                            <span>{role.slug}</span>
                          </button>
                        );
                      })}
                    </div>
                    <div className="inline-danger">
                      <button type="button" className="text-button" onClick={() => revokeSessions.mutate(user.id)}>
                        Sign out all sessions
                      </button>
                      <button
                        type="button"
                        className="text-button danger-text"
                        onClick={() => { if (confirm(`Delete ${user.username}?`)) remove.mutate(user.id); }}
                      >
                        Delete account
                      </button>
                    </div>
                  </div>
                )}
              </article>
            );
          })}
          {!visibleUsers.length && <p className="empty-state">No people match that search.</p>}
        </div>
      </section>
    </div>
  );
}

function initials(name: string): string {
  return name.split(/\s+/).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
}

/** Vocabulary published by /api/meta, so the UI and consumers share one list. */
function PermissionPicker({
  selected,
  disabled,
  onChange,
}: {
  selected: string[];
  disabled?: boolean;
  onChange: (next: string[]) => void;
}) {
  const meta = useQuery(metaQuery);
  const vocabulary = meta.data?.permissions ?? [];
  const groups = useMemo(() => {
    const byProduct = new Map<string, typeof vocabulary>();
    for (const entry of vocabulary) {
      byProduct.set(entry.product, [...(byProduct.get(entry.product) ?? []), entry]);
    }
    return [...byProduct];
  }, [vocabulary]);
  const extras = selected.filter((key) => !vocabulary.some((entry) => entry.key === key));

  const toggle = (key: string) =>
    onChange(selected.includes(key) ? selected.filter((item) => item !== key) : [...selected, key]);

  return (
    <fieldset disabled={disabled} className="permission-picker">
      <legend>Permissions</legend>
      {groups.map(([product, entries]) => (
        <div key={product} className="perm-group">
          <span className="perm-product">{product}</span>
          <div className="permission-grid">
            {entries.map((entry) => (
              <button
                key={entry.key}
                type="button"
                disabled={disabled}
                className={selected.includes(entry.key) ? "permission-option on" : "permission-option"}
                aria-pressed={selected.includes(entry.key)}
                onClick={() => toggle(entry.key)}
              >
                <span className="permission-check" aria-hidden>{selected.includes(entry.key) ? "✓" : ""}</span>
                <span>
                  <strong>{entry.key}</strong>
                  <small>{entry.description}</small>
                </span>
              </button>
            ))}
          </div>
        </div>
      ))}
      {extras.length > 0 && (
        <div className="perm-group">
          <span className="perm-product">product-defined</span>
          <div className="permission-grid">
            {extras.map((key) => (
              <button
                key={key}
                type="button"
                disabled={disabled}
                className="permission-option on"
                aria-pressed="true"
                onClick={() => toggle(key)}
              >
                <span className="permission-check" aria-hidden>✓</span>
                <span><strong>{key}</strong><small>Product-defined capability</small></span>
              </button>
            ))}
          </div>
        </div>
      )}
      <label>
        Add a permission not listed above
        <input
          placeholder="product.action or product.*"
          disabled={disabled}
          onKeyDown={(event) => {
            if (event.key !== "Enter") return;
            event.preventDefault();
            const value = event.currentTarget.value.trim().toLowerCase();
            if (value && !selected.includes(value)) onChange([...selected, value]);
            event.currentTarget.value = "";
          }}
        />
      </label>
    </fieldset>
  );
}

function AccountPanel({
  principal,
  onToast,
}: {
  principal: Principal | undefined;
  onToast: (message: string) => void;
}) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");

  const change = useMutation({
    mutationFn: () =>
      api("/api/session/password", {
        method: "POST",
        body: JSON.stringify({ currentPassword, newPassword }),
      }),
    onSuccess: () => {
      setCurrentPassword("");
      setNewPassword("");
      onToast("Password changed — sign in again");
      window.setTimeout(() => window.location.reload(), 1_200);
    },
    onError: (error: Error) => onToast(error.message),
  });

  return (
    <div className="panel-grid">
      <section className="panel">
        <h2>Signed in as</h2>
        <div className="table">
          <article className="row">
            <div>
              <strong>{principal?.displayName ?? "Unknown"}</strong>
              <span className="mono">{principal?.sub}</span>
              <span className="perms">{principal?.permissions.join(", ") || "—"}</span>
            </div>
          </article>
        </div>
      </section>

      <section className="panel">
        <h2>Change password</h2>
        {principal?.kind === "user" ? (
          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              change.mutate();
            }}
          >
            <label>
              Current password
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </label>
            <label>
              New password
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                autoComplete="new-password"
                required
              />
            </label>
            <p className="muted">All sessions are signed out, including this one.</p>
            <button className="button primary" type="submit" disabled={change.isPending}>
              Change password
            </button>
          </form>
        ) : (
          <p className="muted">
            Only interactive users have a password. This principal resolved as{" "}
            <code>{principal?.kind}</code>.
          </p>
        )}
      </section>
    </div>
  );
}

function RolesPanel({ onToast }: { onToast: (message: string) => void }) {
  const queryClient = useQueryClient();
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => api<Role[]>("/api/roles") });
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [permissions, setPermissions] = useState<string[]>(["identity.read"]);
  const [editing, setEditing] = useState<Role | null>(null);
  const [creating, setCreating] = useState(false);

  const create = useMutation({
    mutationFn: () =>
      api<Role>("/api/roles", {
        method: "POST",
        body: JSON.stringify({ slug, name, description, permissions }),
      }),
    onSuccess: async () => {
      setSlug("");
      setName("");
      setDescription("");
      setPermissions(["identity.read"]);
      setCreating(false);
      await queryClient.invalidateQueries({ queryKey: ["roles"] });
      onToast("Role created");
    },
    onError: (error: Error) => onToast(error.message),
  });

  const save = useMutation({
    mutationFn: (role: Role) =>
      api<Role>(`/api/roles/${role.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          name: role.name,
          description: role.description,
          permissions: role.permissions,
        }),
      }),
    onSuccess: async () => {
      setEditing(null);
      await queryClient.invalidateQueries({ queryKey: ["roles"] });
      onToast("Role updated");
    },
    onError: (error: Error) => onToast(error.message),
  });

  const remove = useMutation({
    mutationFn: (id: number) => api<void>(`/api/roles/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["roles"] });
      onToast("Role deleted");
    },
    onError: (error: Error) => onToast(error.message),
  });

  return (
    <div className="resource-view">
      <div className="resource-toolbar">
        <div className="toolbar-summary">
          <strong>{roles.data?.length ?? 0} roles</strong>
          <span>Role names are labels; permissions are the enforcement contract.</span>
        </div>
        <button
          type="button"
          className="button primary"
          onClick={() => { setEditing(null); setCreating((open) => !open); }}
        >
          {creating ? "Close" : "Create role"}
        </button>
      </div>

      {(editing || creating) && (
        <section className="editor-panel" aria-label={editing ? `Edit ${editing.slug}` : "Create role"}>
          <div className="section-heading">
            <div>
              <span className="eyebrow">{editing ? "Role settings" : "New access role"}</span>
              <h2>{editing ? `Edit ${editing.name}` : "Create an access role"}</h2>
              <p>{editing ? editing.slug : "Group only the capabilities this role needs."}</p>
            </div>
          </div>
          {editing ? (
          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              save.mutate(editing);
            }}
          >
            <label>
              Name
              <input
                value={editing.name}
                onChange={(e) => setEditing({ ...editing, name: e.target.value })}
              />
            </label>
            <label>
              Description
              <textarea
                value={editing.description}
                onChange={(e) => setEditing({ ...editing, description: e.target.value })}
                rows={3}
              />
            </label>
            {editing.permissionsLocked ? (
              <div className="permission-lock">
                <span className="permission-check" aria-hidden>✓</span>
                <div>
                  <strong>* · Full suite access</strong>
                  <p>
                    This capability is fixed so Identity cannot be locked out. Name and
                    description remain editable.
                  </p>
                </div>
              </div>
            ) : (
              <PermissionPicker
                selected={editing.permissions}
                onChange={(next) => setEditing({ ...editing, permissions: next })}
              />
            )}
            <div className="row-actions">
              <button className="button primary" type="submit">
                Save
              </button>
              <button type="button" className="button" onClick={() => setEditing(null)}>
                Cancel
              </button>
            </div>
          </form>
        ) : (
          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              create.mutate();
            }}
          >
            <label>
              Slug
              <input value={slug} onChange={(e) => setSlug(e.target.value)} required />
            </label>
            <label>
              Name
              <input value={name} onChange={(e) => setName(e.target.value)} required />
            </label>
            <label>
              Description
              <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} />
            </label>
            <PermissionPicker selected={permissions} onChange={setPermissions} />
            <button className="button primary" type="submit" disabled={create.isPending}>
              Create role
            </button>
          </form>
          )}
        </section>
      )}

      <section className="list-panel">
        <div className="list-header role-grid">
          <span>Role</span>
          <span>Capabilities</span>
          <span>Type</span>
          <span className="align-right">Actions</span>
        </div>
        <div className="data-list">
          {(roles.data ?? []).map((role) => (
            <article key={role.id} className="data-row role-grid">
              <div className="role-identity">
                <strong>{role.name}</strong>
                <small>{role.slug}</small>
                <p>{role.description}</p>
              </div>
              <div className="permission-summary">
                <strong>{role.permissions.length}</strong>
                <span>{role.permissions.slice(0, 3).join(" · ")}{role.permissions.length > 3 ? " · …" : ""}</span>
              </div>
              <div className="tag-list">
                <span className="tag">{role.builtin ? "Built in" : "Custom"}</span>
                {role.permissionsLocked && <span className="tag fixed">Fixed</span>}
              </div>
              <div className="row-actions align-right">
                <button
                  type="button"
                  className="button small"
                  onClick={() => { setCreating(false); setEditing({ ...role }); }}
                >
                  Edit
                </button>
                {!role.builtin && (
                  <button
                    type="button"
                    className="button small quiet danger-text"
                    onClick={() => { if (confirm(`Delete role ${role.slug}?`)) remove.mutate(role.id); }}
                  >
                    Delete
                  </button>
                )}
              </div>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

function TokensPanel({
  createdToken,
  onCreatedToken,
  onToast,
}: {
  createdToken: string | null;
  onCreatedToken: (token: string | null) => void;
  onToast: (message: string) => void;
}) {
  const queryClient = useQueryClient();
  const tokens = useQuery({
    queryKey: ["tokens"],
    queryFn: () => api<ServiceToken[]>("/api/tokens"),
  });
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => api<Role[]>("/api/roles") });
  const [name, setName] = useState("");
  const [roleSlugs, setRoleSlugs] = useState<string[]>([]);
  const [expiresInDays, setExpiresInDays] = useState("");
  const [showCreate, setShowCreate] = useState(false);

  const roleOptions = useMemo(() => roles.data ?? [], [roles.data]);

  const create = useMutation({
    mutationFn: () =>
      api<ServiceToken>("/api/tokens", {
        method: "POST",
        body: JSON.stringify({
          name,
          roleSlugs,
          expiresInDays: expiresInDays ? Number(expiresInDays) : undefined,
        }),
      }),
    onSuccess: async (token) => {
      setName("");
      setExpiresInDays("");
      setRoleSlugs([]);
      setShowCreate(false);
      onCreatedToken(token.token ?? null);
      await queryClient.invalidateQueries({ queryKey: ["tokens"] });
      onToast("Service token created — copy it now");
    },
    onError: (error: Error) => onToast(error.message),
  });

  const remove = useMutation({
    mutationFn: (id: number) => api<void>(`/api/tokens/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["tokens"] });
      onToast("Token revoked");
    },
    onError: (error: Error) => onToast(error.message),
  });

  return (
    <div className="resource-view">
      <div className="resource-toolbar">
        <div className="toolbar-summary">
          <strong>{tokens.data?.length ?? 0} active credentials</strong>
          <span>Use one short-lived, least-privilege token per service direction.</span>
        </div>
        <button type="button" className="button primary" onClick={() => setShowCreate((open) => !open)}>
          {showCreate ? "Close" : "Mint token"}
        </button>
      </div>

        {createdToken && (
          <div className="secret" role="status">
            <div>
              <strong>Copy this token now</strong>
              <span>It cannot be shown again after you dismiss it.</span>
              <code>{createdToken}</code>
            </div>
            <button type="button" className="button small" onClick={() => onCreatedToken(null)}>Dismiss</button>
          </div>
        )}

      {showCreate && (
        <section className="editor-panel" aria-label="Mint service token">
          <div className="section-heading">
            <div>
              <span className="eyebrow">Machine credential</span>
              <h2>Mint a service token</h2>
              <p>The secret is displayed once. Prefer a scoped service role and an expiry.</p>
            </div>
          </div>
        <form
          className="form-grid token-form"
          onSubmit={(event) => {
            event.preventDefault();
            create.mutate();
          }}
        >
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} required placeholder="helix-bot" />
          </label>
          <label>
            Expires in days (blank = never)
            <input
              type="number"
              min={1}
              value={expiresInDays}
              onChange={(e) => setExpiresInDays(e.target.value)}
              placeholder="90"
            />
          </label>
          <fieldset className="form-span">
            <legend>Roles</legend>
            <div className="choice-grid compact">
              {roleOptions.map((role) => {
                const on = roleSlugs.includes(role.slug);
                return (
                  <button
                    key={role.slug}
                    type="button"
                    className={on ? "choice on" : "choice"}
                    aria-pressed={on}
                    onClick={() =>
                      setRoleSlugs((current) =>
                        on ? current.filter((slug) => slug !== role.slug) : [...current, role.slug],
                      )
                    }
                  >
                    <strong>{role.name}</strong>
                    <span>{role.slug}</span>
                  </button>
                );
              })}
            </div>
          </fieldset>
          <div className="form-actions form-span">
            <button type="button" className="button" onClick={() => setShowCreate(false)}>Cancel</button>
            <button className="button primary" type="submit" disabled={create.isPending || !roleSlugs.length}>
              Create token
            </button>
          </div>
        </form>
        </section>
      )}

      <section className="list-panel">
        <div className="list-header token-grid">
          <span>Credential</span>
          <span>Access</span>
          <span>Activity</span>
          <span className="align-right">Actions</span>
        </div>
        <div className="data-list">
          {(tokens.data ?? []).map((token) => (
            <article key={token.id} className="data-row token-grid">
              <div className="role-identity">
                <strong>{token.name}</strong>
                <small className="mono">{token.tokenPrefix}…</small>
              </div>
              <div className="tag-list">
                {token.roleSlugs.map((slug) => <span key={slug} className="tag">{slug}</span>)}
              </div>
              <div className="token-activity">
                <strong>{token.lastUsedAt ? `Used ${formatTime(token.lastUsedAt)}` : "Never used"}</strong>
                <span>
                  {token.expiresAt
                    ? `${token.expiresAt < Date.now() ? "Expired" : "Expires"} ${formatTime(token.expiresAt)}`
                    : "No expiry"}
                </span>
              </div>
              <div className="row-actions align-right">
                <button
                  type="button"
                  className="button small quiet danger-text"
                  onClick={() => { if (confirm(`Revoke ${token.name}?`)) remove.mutate(token.id); }}
                >
                  Revoke
                </button>
              </div>
            </article>
          ))}
          {!tokens.data?.length && <p className="empty-state">No service tokens yet.</p>}
        </div>
      </section>
    </div>
  );
}
