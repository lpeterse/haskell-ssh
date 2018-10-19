.PHONY: test hpc

test:
	stack test --ta "-t 3 -j1" --coverage

hpc: test
	stack hpc report hssh # --open

hp:
	./profile.sh
	sleep 3
	hp2pretty hssh-demo.hp
	chromium-browser hssh-demo.svg || true
	chromium hssh-demo.svg || true
