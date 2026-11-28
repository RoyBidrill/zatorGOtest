package fetch

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// MaxFileSize — верхний предел размера одного файла при распаковке
// (защита от архивных бомб).
const MaxFileSize = 512 << 20

// ErrUnsafePath — запись архива выходит за пределы каталога назначения.
var ErrUnsafePath = errors.New("fetch: небезопасный путь в архиве")

// Filter выбирает записи для распаковки. Получает очищенное имя записи
// (разделитель «/», без ведущего «./»); возвращает относительный путь
// назначения и признак «распаковать». Пустой rel при ok=true недопустим.
type Filter func(name string, mode os.FileMode) (rel string, ok bool)

// CleanEntryName проверяет и нормализует имя записи tar. Отвергает
// абсолютные пути, «..», обратные слэши, буквы дисков и NUL.
func CleanEntryName(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) || strings.Contains(name, `\`) {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, name)
	}
	if strings.HasPrefix(name, "/") || (len(name) >= 2 && name[1] == ':') {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return "", fmt.Errorf("%w: %q", ErrUnsafePath, name)
		}
	}
	clean := path.Clean(name)
	if clean == "." {
		return ".", nil
	}
	return clean, nil
}

// SafeUntar распаковывает tar.gz archive в dest, отвергая записи с «..»
// и абсолютными путями (проверяются все записи архива).
func SafeUntar(archive, dest string) error {
	return SafeUntarFiltered(archive, dest, nil)
}

// SafeUntarFiltered — как SafeUntar, но распаковывает только записи,
// принятые filter (nil — все). Безопасность проверяется для всех записей,
// включая отфильтрованные.
func SafeUntarFiltered(archive, dest string, filter Filter) error {
	// Первый проход: валидация всего архива до записи на диск.
	if err := ValidateTarGz(archive); err != nil {
		return err
	}
	return SafeUntarFilteredValidated(archive, dest, filter)
}

// SafeUntarFilteredValidated распаковывает предварительно провалидированный tar.gz
// (например, после ListTarGz), сохраняя все проверки путей для каждой записи.
func SafeUntarFilteredValidated(archive, dest string, filter Filter) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("fetch: %s: %w", archive, err)
	}
	defer gz.Close()

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return err
	}

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("fetch: %s: %w", archive, err)
		}
		name, err := CleanEntryName(hdr.Name)
		if err != nil {
			return err
		}
		if name == "." {
			continue
		}
		rel := name
		if filter != nil {
			var ok bool
			rel, ok = filter(name, hdr.FileInfo().Mode())
			if !ok {
				continue
			}
			if rel, err = CleanEntryName(rel); err != nil {
				return err
			}
		}
		target, err := joinInside(absDest, rel)
		if err != nil {
			return err
		}
		if err := extractEntry(tr, hdr, absDest, target); err != nil {
			return err
		}
	}
}

// ValidateTarGz читает архив целиком и проверяет имена и ссылки записей.
func ValidateTarGz(archive string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("fetch: %s: %w", archive, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("fetch: %s: %w", archive, err)
		}
		name, err := CleanEntryName(hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeSymlink:
			if err := checkSymlink(name, hdr.Linkname); err != nil {
				return err
			}
		case tar.TypeLink:
			if _, err := CleanEntryName(hdr.Linkname); err != nil {
				return err
			}
		}
	}
}

// ListTarGz возвращает очищенные имена всех записей архива (после проверки
// безопасности имён и ссылок).
func ListTarGz(archive string) ([]string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("fetch: %s: %w", archive, err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, fmt.Errorf("fetch: %s: %w", archive, err)
		}
		name, err := CleanEntryName(hdr.Name)
		if err != nil {
			return nil, err
		}
		switch hdr.Typeflag {
		case tar.TypeSymlink:
			if err := checkSymlink(name, hdr.Linkname); err != nil {
				return nil, err
			}
		case tar.TypeLink:
			if _, err := CleanEntryName(hdr.Linkname); err != nil {
				return nil, err
			}
		}
		if name != "." {
			names = append(names, name)
		}
	}
}

// checkSymlink отвергает символические ссылки, выходящие за корень архива.
func checkSymlink(name, link string) error {
	if link == "" || strings.ContainsRune(link, 0) || strings.Contains(link, `\`) ||
		strings.HasPrefix(link, "/") || (len(link) >= 2 && link[1] == ':') {
		return fmt.Errorf("%w: символическая ссылка %q -> %q", ErrUnsafePath, name, link)
	}
	resolved := path.Join(path.Dir(name), link)
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("%w: символическая ссылка %q -> %q", ErrUnsafePath, name, link)
	}
	return nil
}

func joinInside(absDest, rel string) (string, error) {
	target := filepath.Join(absDest, filepath.FromSlash(rel))
	r, err := filepath.Rel(absDest, target)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, rel)
	}
	return target, nil
}

func extractEntry(tr *tar.Reader, hdr *tar.Header, absDest, target string) error {
	switch hdr.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(target, 0o755)
	case tar.TypeReg, tar.TypeRegA:
		if hdr.Size > MaxFileSize {
			return fmt.Errorf("fetch: файл %q слишком большой (%d байт)", hdr.Name, hdr.Size)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if hdr.FileInfo().Mode()&0o111 != 0 {
			mode = 0o755
		}
		_ = os.Remove(target)
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(tr, MaxFileSize)); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		return os.Chmod(target, mode)
	case tar.TypeSymlink:
		// Относительная цель проверена в ValidateTarGz; дополнительно
		// убеждаемся, что цель остаётся внутри каталога назначения.
		resolved := filepath.Join(filepath.Dir(target), filepath.FromSlash(hdr.Linkname))
		if _, err := joinInside(absDest, mustRel(absDest, resolved)); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		_ = os.Remove(target)
		return os.Symlink(hdr.Linkname, target)
	default:
		// Жёсткие ссылки, устройства, FIFO и т.п. не распаковываем.
		return nil
	}
}

func mustRel(base, target string) string {
	r, err := filepath.Rel(base, target)
	if err != nil {
		return ".."
	}
	return filepath.ToSlash(r)
}
