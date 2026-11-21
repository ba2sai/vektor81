export class WorkerEntrypoint<Env = unknown, Props = unknown> {
  protected ctx: unknown;
  protected env: Env;
  protected props: Props;

  constructor(ctx?: unknown, env?: Env, props?: Props) {
    this.ctx = ctx;
    this.env = (env ?? {}) as Env;
    this.props = (props ?? {}) as Props;
  }
}
