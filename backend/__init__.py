from __future__ import annotations

import os
from pathlib import Path


# Keep handles alive for process lifetime; dropping them can undo DLL search paths.
_DLL_HANDLES: list[object] = []


def _configure_windows_gtk_runtime() -> None:
	if os.name != "nt":
		return

	candidate_bins = [
		Path("D:/Program Files/GTK3-Runtime Win64/bin"),
		Path("C:/Program Files/GTK3-Runtime Win64/bin"),
		Path("C:/Program Files/GTK3-Runtime/bin"),
		Path("C:/Program Files (x86)/GTK3-Runtime Win64/bin"),
		Path("C:/Program Files (x86)/GTK3-Runtime/bin"),
	]

	extra = str(os.getenv("GTK_RUNTIME_BIN", "")).strip()
	if extra:
		candidate_bins.insert(0, Path(extra))

	add_dll = getattr(os, "add_dll_directory", None)
	path_parts = os.environ.get("PATH", "").split(os.pathsep)

	for bin_path in candidate_bins:
		if not bin_path.exists():
			continue

		bin_str = str(bin_path)
		if bin_str not in path_parts:
			os.environ["PATH"] = bin_str + os.pathsep + os.environ.get("PATH", "")
			path_parts.insert(0, bin_str)

		if callable(add_dll):
			try:
				handle = add_dll(bin_str)
			except OSError:
				continue
			_DLL_HANDLES.append(handle)


_configure_windows_gtk_runtime()
