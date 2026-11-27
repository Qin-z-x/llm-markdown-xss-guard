# Deployment notes

The service was deployed successfully at 14:05 UTC. **No action is required.**

- build: green
- tests: 212 passed
- rollback plan: documented in `runbook.md`

Read the [deployment guide](https://example.com/docs/deploy) if you need details.

```bash
kubectl rollout status deployment/api
kubectl get pods -l app=api
```

Inline code such as `<img onerror=x>` or `<script>` is documentation, not HTML.
