
.PHONY: test hpc

test:
	stack test --ta "-t 3 -j1" --coverage

hpc: test
	stack hpc report hssh --open
