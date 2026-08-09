import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest';

// ── Shared mock data builders ──

function makeProvidersResponse(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    google: false,
    github: false,
    authMode: 'oauth',
    ...overrides,
  };
}

function createFetchHandler(providersResponse: Record<string, unknown>) {
  return (url: string | URL | Request): Promise<Response> => {
    const path = typeof url === 'string' ? url : url instanceof URL ? url.pathname : url.url;

    if (path.includes('/auth/providers')) {
      return Promise.resolve(
        new Response(JSON.stringify(providersResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }

    return Promise.resolve(new Response('', { status: 404 }));
  };
}

// Import the component module once so the custom element is only registered once.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let ScionLoginPage: any;

async function createComponent(
  fetchHandler: (url: string | URL | Request, init?: RequestInit) => Promise<Response>,
) {
  vi.stubGlobal('fetch', vi.fn(fetchHandler));
  const el = document.createElement('scion-login-page') as InstanceType<typeof ScionLoginPage>;
  document.body.appendChild(el);
  await el.updateComplete;
  await new Promise((resolve) => setTimeout(resolve, 0));
  await el.updateComplete;
  return el;
}

function query(el: HTMLElement, selector: string): Element | null {
  return el.shadowRoot?.querySelector(selector) ?? null;
}

// ── Tests ──

describe('scion-login-page', () => {
  let element: HTMLElement | null = null;

  beforeAll(async () => {
    vi.stubGlobal('fetch', vi.fn(createFetchHandler(makeProvidersResponse())));
    const mod = await import('./login.js');
    ScionLoginPage = mod.ScionLoginPage;
  });

  afterEach(() => {
    element?.remove();
    element = null;
    vi.restoreAllMocks();
  });

  it('renders the custom SSO button with the server display name and correct href when custom is enabled', async () => {
    element = await createComponent(
      createFetchHandler(makeProvidersResponse({ custom: true, customDisplayName: 'Acme SSO' })),
    );

    const customBtn = query(element, '.provider-btn.custom');
    expect(customBtn).toBeTruthy();
    expect(customBtn?.textContent).toContain('Continue with Acme SSO');
    expect(customBtn?.getAttribute('href')).toContain('/auth/login/custom');
  });

  it('renders no custom button when custom is false and customDisplayName is absent', async () => {
    element = await createComponent(createFetchHandler(makeProvidersResponse({ custom: false })));

    expect(query(element, '.provider-btn.custom')).toBeNull();
  });
});
