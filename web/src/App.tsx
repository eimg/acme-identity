import { useMemo, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type {
  IdentityMeta,
  Principal,
  Role,
  ServiceToken,
  User,
} from "../../src/types";
import { api, formatTime } from "./api";

type Tab = "users" | "roles" | "tokens";

interface SessionResponse {
  principal: Principal;
  user: User | null;
}

export function App() {
  const queryClient = useQueryClient();
  const meta = useQuery({
    queryKey: ["meta"],
    queryFn: () => api<IdentityMeta>("/api/meta"),
  });
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
  const [tab, setTab] = useState<Tab>("users");
  const [toast, setToast] = useState("");
  const [createdToken, setCreatedToken] = useState<string | null>(null);

  const showToast = (message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 2_800);
  };

  const signedIn = Boolean(session.data?.principal);
  const isOff = meta.data?.authMode === "off";
  const canManage =
    isOff ||
    session.data?.principal.roles.includes("admin") ||
    session.data?.principal.permissions.includes("*");

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

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <div className="mark" aria-hidden />
          <div>
            <strong>Acme Identity</strong>
            <span>Thin suite auth layer</span>
          </div>
        </div>
        <div className="topbar-meta">
          <span className={`mode-pill mode-${meta.data?.authMode ?? "local"}`}>
            mode · {meta.data?.authMode}
          </span>
          <span className="who">
            {session.data?.principal.displayName ?? "Admin"}
            <em>{session.data?.principal.roles.join(", ")}</em>
          </span>
          {!isOff && (
            <button type="button" className="button ghost" onClick={() => signOut.mutate()}>
              Sign out
            </button>
          )}
        </div>
      </header>

      {isOff && (
        <div className="banner">
          Auth mode is <code>off</code>. All callers resolve as <strong>admin</strong> for local
          feature testing. Set <code>ACME_AUTH_MODE=local</code> for real sessions.
        </div>
      )}

      <nav className="tabs">
        {(["users", "roles", "tokens"] as Tab[]).map((item) => (
          <button
            key={item}
            type="button"
            className={tab === item ? "tab active" : "tab"}
            onClick={() => setTab(item)}
          >
            {item}
          </button>
        ))}
      </nav>

      <main className="content">
        {!canManage ? (
          <p className="muted">Admin role required to manage identity.</p>
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
      </main>

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

  return (
    <div className="panel-grid">
      <section className="panel">
        <h2>Users</h2>
        <div className="table">
          {(users.data ?? []).map((user) => (
            <article key={user.id} className="row">
              <div>
                <strong>{user.displayName}</strong>
                <span className="mono">
                  {user.username}
                  {!user.active && " · inactive"}
                </span>
              </div>
              <div className="chips">
                {(roles.data ?? []).map((role) => {
                  const on = user.roleSlugs.includes(role.slug);
                  return (
                    <button
                      key={role.slug}
                      type="button"
                      className={on ? "chip on" : "chip"}
                      onClick={() => {
                        const next = on
                          ? user.roleSlugs.filter((slug) => slug !== role.slug)
                          : [...user.roleSlugs, role.slug];
                        if (!next.length) {
                          onToast("At least one role is required");
                          return;
                        }
                        patchRoles.mutate({ id: user.id, next });
                      }}
                    >
                      {role.slug}
                    </button>
                  );
                })}
              </div>
              <div className="row-actions">
                <button type="button" className="button small" onClick={() => toggleActive.mutate(user)}>
                  {user.active ? "Disable" : "Enable"}
                </button>
                <button
                  type="button"
                  className="button small danger"
                  onClick={() => {
                    if (confirm(`Delete ${user.username}?`)) remove.mutate(user.id);
                  }}
                >
                  Delete
                </button>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2>New user</h2>
        <form
          className="stack"
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
          <fieldset>
            <legend>Roles</legend>
            <div className="chips">
              {(roles.data ?? []).map((role) => {
                const on = roleSlugs.includes(role.slug);
                return (
                  <button
                    key={role.slug}
                    type="button"
                    className={on ? "chip on" : "chip"}
                    onClick={() =>
                      setRoleSlugs((current) =>
                        on ? current.filter((slug) => slug !== role.slug) : [...current, role.slug],
                      )
                    }
                  >
                    {role.slug}
                  </button>
                );
              })}
            </div>
          </fieldset>
          <button className="button primary" type="submit" disabled={create.isPending}>
            Create user
          </button>
        </form>
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
  const [permissionsText, setPermissionsText] = useState("identity.read");
  const [editing, setEditing] = useState<Role | null>(null);

  const create = useMutation({
    mutationFn: () =>
      api<Role>("/api/roles", {
        method: "POST",
        body: JSON.stringify({
          slug,
          name,
          description,
          permissions: permissionsText
            .split(/[\n,]/)
            .map((item) => item.trim())
            .filter(Boolean),
        }),
      }),
    onSuccess: async () => {
      setSlug("");
      setName("");
      setDescription("");
      setPermissionsText("identity.read");
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
    <div className="panel-grid">
      <section className="panel">
        <h2>Roles</h2>
        <div className="table">
          {(roles.data ?? []).map((role) => (
            <article key={role.id} className="row role-row">
              <div>
                <strong>
                  {role.name} <span className="mono">{role.slug}</span>
                  {role.builtin && <em className="badge">builtin</em>}
                </strong>
                <span>{role.description}</span>
                <span className="perms">{role.permissions.join(", ") || "—"}</span>
              </div>
              <div className="row-actions">
                <button type="button" className="button small" onClick={() => setEditing({ ...role })}>
                  Edit
                </button>
                {!role.builtin && (
                  <button
                    type="button"
                    className="button small danger"
                    onClick={() => {
                      if (confirm(`Delete role ${role.slug}?`)) remove.mutate(role.id);
                    }}
                  >
                    Delete
                  </button>
                )}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2>{editing ? `Edit ${editing.slug}` : "New role"}</h2>
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
            <label>
              Permissions (comma or newline)
              <textarea
                value={editing.permissions.join("\n")}
                onChange={(e) =>
                  setEditing({
                    ...editing,
                    permissions: e.target.value
                      .split(/[\n,]/)
                      .map((item) => item.trim())
                      .filter(Boolean),
                  })
                }
                rows={6}
              />
            </label>
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
            <label>
              Permissions
              <textarea
                value={permissionsText}
                onChange={(e) => setPermissionsText(e.target.value)}
                rows={5}
              />
            </label>
            <button className="button primary" type="submit" disabled={create.isPending}>
              Create role
            </button>
          </form>
        )}
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
  const [roleSlugs, setRoleSlugs] = useState<string[]>(["operator"]);

  const roleOptions = useMemo(() => roles.data ?? [], [roles.data]);

  const create = useMutation({
    mutationFn: () =>
      api<ServiceToken>("/api/tokens", {
        method: "POST",
        body: JSON.stringify({ name, roleSlugs }),
      }),
    onSuccess: async (token) => {
      setName("");
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
    <div className="panel-grid">
      <section className="panel">
        <h2>Service tokens</h2>
        <p className="muted">
          Machine principals for Issues ↔ Helix ↔ Projects and other suite edges. Shown once at
          creation.
        </p>
        {createdToken && (
          <div className="secret">
            <code>{createdToken}</code>
            <button type="button" className="button small" onClick={() => onCreatedToken(null)}>
              Dismiss
            </button>
          </div>
        )}
        <div className="table">
          {(tokens.data ?? []).map((token) => (
            <article key={token.id} className="row">
              <div>
                <strong>{token.name}</strong>
                <span className="mono">
                  {token.tokenPrefix}… · {token.roleSlugs.join(", ")}
                </span>
                <span className="muted">
                  Created {formatTime(token.createdAt)}
                  {token.lastUsedAt ? ` · last used ${formatTime(token.lastUsedAt)}` : ""}
                </span>
              </div>
              <button
                type="button"
                className="button small danger"
                onClick={() => {
                  if (confirm(`Revoke ${token.name}?`)) remove.mutate(token.id);
                }}
              >
                Revoke
              </button>
            </article>
          ))}
          {!tokens.data?.length && <p className="muted">No service tokens yet.</p>}
        </div>
      </section>

      <section className="panel">
        <h2>Mint token</h2>
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            create.mutate();
          }}
        >
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} required placeholder="helix-bot" />
          </label>
          <fieldset>
            <legend>Roles</legend>
            <div className="chips">
              {roleOptions.map((role) => {
                const on = roleSlugs.includes(role.slug);
                return (
                  <button
                    key={role.slug}
                    type="button"
                    className={on ? "chip on" : "chip"}
                    onClick={() =>
                      setRoleSlugs((current) =>
                        on ? current.filter((slug) => slug !== role.slug) : [...current, role.slug],
                      )
                    }
                  >
                    {role.slug}
                  </button>
                );
              })}
            </div>
          </fieldset>
          <button className="button primary" type="submit" disabled={create.isPending || !roleSlugs.length}>
            Create token
          </button>
        </form>
      </section>
    </div>
  );
}
