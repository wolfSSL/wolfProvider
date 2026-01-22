# Github workflow pre-processing

## TLDR
Run `make` from this directory to regenerate the yamls in the `.github/workflows` directory. Then commit those files without further modification.

## Details
In order to unify large chunks of code, we pre-process the workflow yamls to insert common blocks of code. 

The files `*.yml.in` are the pre-processed workflow files. Manually edit these, not the generated ones in `.github/workflows`. Run `make` here to regenerate any outdated workflows.

The workflow `generated-workflows.yml` ensures that the pre-processing has been done.

### Syntax
Designed to be as lightweight and yaml-like as possible, insert the following line structure into a `.yml.in` file.

`  include: "path/to/file.yml.in"`

Any leading whitespace indentation is preserved.
