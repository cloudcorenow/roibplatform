import { describe, it, expect, vi } from 'vitest';
import { toCsv, downloadCsv } from '../utils/exportCsv';

// Mock URL and document for download tests
global.URL.createObjectURL = vi.fn(() => 'mock-url');
global.URL.revokeObjectURL = vi.fn();

Object.defineProperty(document, 'createElement', {
  value: vi.fn(() => ({
    href: '',
    download: '',
    click: vi.fn(),
    remove: vi.fn()
  }))
});

Object.defineProperty(document.body, 'appendChild', {
  value: vi.fn()
});

describe('CSV Export Utils', () => {
  describe('toCsv', () => {
    it('converts array of objects to CSV string', () => {
      const data = [
        { name: 'John', age: 30, city: 'New York' },
        { name: 'Jane', age: 25, city: 'Los Angeles' }
      ];

      const result = toCsv(data);
      const expected = 'name,age,city\r\nJohn,30,New York\r\nJane,25,Los Angeles';
      
      expect(result).toBe(expected);
    });

    it('handles empty array', () => {
      const result = toCsv([]);
      expect(result).toBe('');
    });

    it('escapes CSV special characters', () => {
      const data = [
        { name: 'John, Jr.', description: 'Has "quotes"', notes: 'Line\nbreak' }
      ];

      const result = toCsv(data);
      expect(result).toContain('"John, Jr."');
      expect(result).toContain('"Has ""quotes"""');
      expect(result).toContain('"Line\nbreak"');
    });

    it('uses custom headers when provided', () => {
      const data = [
        { name: 'John', age: 30, city: 'New York', unused: 'value' }
      ];

      const result = toCsv(data, ['name', 'age']);
      const lines = result.split('\r\n');
      
      expect(lines[0]).toBe('name,age');
      expect(lines[1]).toBe('John,30');
    });

    it('handles null and undefined values', () => {
      const data = [
        { name: 'John', age: null, city: undefined }
      ];

      const result = toCsv(data);
      expect(result).toContain('John,,');
    });
  });

  describe('downloadCsv', () => {
    it('creates download link with correct attributes', () => {
      const mockElement = {
        href: '',
        download: '',
        click: vi.fn(),
        remove: vi.fn()
      };
      
      vi.mocked(document.createElement).mockReturnValue(mockElement as any);

      downloadCsv('test.csv', 'name,age\r\nJohn,30');

      expect(document.createElement).toHaveBeenCalledWith('a');
      expect(mockElement.download).toBe('test.csv');
      expect(mockElement.click).toHaveBeenCalled();
      expect(mockElement.remove).toHaveBeenCalled();
    });

    it('adds BOM for Excel compatibility', () => {
      const createObjectURL = vi.mocked(URL.createObjectURL);
      
      downloadCsv('test.csv', 'data');
      
      expect(createObjectURL).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'text/csv;charset=utf-8;'
        })
      );
    });
  });
});