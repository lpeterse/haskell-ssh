.PHONY: install test hpc hp doc clean

install:
	stack install

test:
	stack test --ta "-t 3 -j1" --coverage

hpc: test
	stack hpc report hssh # --open

hp:
	./profile.sh
	sleep 3
	hp2pretty hssh-client.hp
	chromium-browser hssh-client.svg || true
	chromium hssh-client.svg || true

doc:
	stack haddock

clean:
	stack clean
	rm *.hp *.prof *.svg
