---
title: CLI autocompletion
---

# Autocompletion

Stratus Red Team uses [cobra](https://github.com/spf13/cobra)'s built-in support to add autocompletions when working with the CLI.

## Setup

* bash: TODO

* zsh: 

```bash
echo "autoload -U compinit; compinit" >> ~/.zshrc
source ~/.zshrc
stratus completion zsh > "${fpath[1]}/_stratus"
```

* fish:

```bash
stratus completion fish > ~/.config/fish/completions/stratus.fish
```

## Sample usage

```bash
stratus deton[tab]
stratus detonate aws[tab][tab]
```