---
title: CLI autocompletion
---

# Autocompletion

Stratus Red Team uses [cobra](https://github.com/spf13/cobra)'s built-in support to add autocompletions when working with the CLI.

## Sample usage

```bash
stratus deton[tab]
stratus detonate aws[tab][tab]
```
## Setup

### Through Homebrew

When installing Stratus Red Team through Homebrew, shell completions are automatically installed for bash, zsh and fish shells.

### Manually

=== "bash"

    Ensure you have [bash-completion](https://github.com/scop/bash-completion) installed (`brew install bash-completion`  / `apt install bash-completion`), then run:

    === "Mac OS"

        ```bash
        # Install bash-completion if necessary
        brew install bash-completion

        stratus completion bash > /usr/local/etc/bash_completion.d/stratus
        echo "source /usr/local/etc/bash_completion" >> ~/.bashrc
        ```

    === "Linux"
    
        ```bash
        # Install bash-completion if necessary
        sudo apt install bash-completion
        
        mkdir -p /etc/bash_completion.d
        stratus completion bash > /etc/bash_completion.d/stratus
        echo "source /etc/bash_completion" >> ~/.bashrc
        ```

=== "zsh"

    ```bash
    echo "autoload -U compinit; compinit" >> ~/.zshrc
    source ~/.zshrc
    stratus completion zsh > "${fpath[1]}/_stratus"
    ```

=== "fish"

    ```bash
    stratus completion fish > ~/.config/fish/completions/stratus.fish
    ```


