# Instrucciones para Claude Code

## Identidad de Git (obligatorio)

Todos los commits y pushes de este repositorio se hacen con la cuenta de GitHub
**Fabricio-Ramirez** (https://github.com/Fabricio-Ramirez), nunca con otra cuenta.

- Autor y committer de cada commit:
  `Fabricio-Ramirez <223577715+Fabricio-Ramirez@users.noreply.github.com>`
- Configurarlo antes de commitear:

  ```bash
  git config user.name "Fabricio-Ramirez"
  git config user.email "223577715+Fabricio-Ramirez@users.noreply.github.com"
  ```

- No usar ningún otro nombre ni correo como autor o committer.
- Antes de hacer push, verificar con `git log -1 --format='%an <%ae> / %cn <%ce>'`.
