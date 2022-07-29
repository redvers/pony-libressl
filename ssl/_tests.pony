use "crypto"

actor Main
  new create(env: Env) =>
    env.out.print("What ho!")
    env.out.print("Version: " + OpenSSL.version())
