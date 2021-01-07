if [[ ! -f 'spack/README.md' ]]; then
  git submodule update --init --recursive
fi

source spack/share/spack/setup-env.sh

spack env activate .

spack install
