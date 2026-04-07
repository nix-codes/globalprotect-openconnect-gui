BIN := gpoc-gui

.PHONY: build run clean deps install uninstall full-install

deps:
	go mod tidy

build: deps
	go build -o $(BIN) .

run: build
	./$(BIN)

clean:
	rm -f $(BIN)

install:
	@test -f $(BIN) || { echo "Binary not found -- run 'make build' first, then re-run 'sudo make install'"; exit 1; }
	@echo "[1/4] Installing binary..."
	install -Dm755 $(BIN) /usr/local/bin/$(BIN)
	@echo "[2/4] Installing icon..."
	install -Dm644 assets/vpn-green.png /usr/share/pixmaps/$(BIN).png
	@echo "[3/4] Installing desktop entry..."
	install -Dm644 assets/$(BIN).desktop /usr/share/applications/$(BIN).desktop
	@echo "[4/4] Installing sudoers rule..."
	sh scripts/install-sudoers.sh
	@echo "Done. Run $(BIN) as a normal user."

uninstall:
	rm -f /usr/local/bin/$(BIN)
	rm -f /usr/share/pixmaps/$(BIN).png
	rm -f /usr/share/applications/$(BIN).desktop
	rm -f /etc/sudoers.d/$(BIN)
	@echo "Uninstalled $(BIN)."

full-install:
	$(MAKE) build
	sudo $(MAKE) install
