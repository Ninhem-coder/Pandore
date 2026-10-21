## Summary

<!-- What does this change and why? Link the related issue, e.g. "Closes #123". -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Refactoring / maintenance

## How was it tested?

<!-- Commands you ran and what you checked in the dashboard. -->

- [ ] Backend: `pytest tests/`
- [ ] Dashboard: `npx vitest run` and `npx vite build`
- [ ] Vanitas server: `pytest tests/`
- [ ] Vanitas agent: `dotnet test EndpointAgent.sln`
- [ ] Manually against a tenant or a test environment

## Checklist

- [ ] No secrets, tenant IDs, device names, user names or e-mail addresses in code, tests, logs or screenshots.
- [ ] New public backend functions are registered in `mcp_server.py` or listed in `EXCLUDED_FROM_MCP`.
- [ ] Vanitas schema changes include an Alembic migration that works on a fresh database.
- [ ] Documentation and `CHANGELOG.md` updated if users are affected.
