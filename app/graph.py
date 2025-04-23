import os
import sys
import tkinter as tk
from tkinter import messagebox, ttk

import matplotlib.pyplot as plt
import pandas as pd
import pyodbc
from scipy.stats import ttest_rel
import numpy as np
from scipy import stats


class ExcelGraphApp:
    def __init__(self, root, patient_id):
        self.root = root
        self.root.title(f"Аналіз даних | Пацієнт {patient_id}")
        self.root.configure(bg="white")
        self.root.geometry("420x600")

        self.patient_id = patient_id
        self.patient_folder = os.path.join(
            "server_database/excel_files/", str(patient_id)
        )
        self.files = []
        self.data = {}
        self.graph_type = "Лінійний"

        default_font = ("Helvetica Neue", 12)
        bold_font = ("Helvetica Neue", 12, "bold")

        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "TButton", font=default_font, padding=6, relief="flat", background="#f0f0f0"
        )
        style.configure("TRadiobutton", font=default_font, background="white")
        style.configure("TLabel", font=default_font, background="white")
        style.configure("TFrame", background="white")

        if not os.path.exists(self.patient_folder):
            messagebox.showerror("Помилка", "Папка пацієнта не знайдена!")
            root.destroy()
            return

        main_frame = ttk.Frame(root, padding=10)
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.columnconfigure(0, weight=1)

        ttk.Label(main_frame, text="Доступні файли", font=bold_font).grid(
            row=0, column=0, sticky="w"
        )
        self.file_listbox = tk.Listbox(
            main_frame,
            selectmode=tk.MULTIPLE,
            font=default_font,
            height=5,
            bd=1,
            relief="solid",
            highlightthickness=0,
        )
        self.file_listbox.grid(row=1, column=0, sticky="ew", pady=5)
        ttk.Button(main_frame, text="🔍 Вибрати файли", command=self.select_files).grid(
            row=2, column=0, pady=(0, 15)
        )

        self.load_files()

        ttk.Label(main_frame, text="Виберіть параметри:", font=bold_font).grid(
            row=3, column=0, sticky="w"
        )
        self.param_listbox = tk.Listbox(
            main_frame,
            selectmode=tk.MULTIPLE,
            height=4,
            font=default_font,
            bd=1,
            relief="solid",
            highlightthickness=0,
        )
        self.param_listbox.grid(row=4, column=0, sticky="ew", pady=5)

        ttk.Label(main_frame, text="Виберіть тип графіка:", font=bold_font).grid(
            row=5, column=0, sticky="w", pady=(10, 0)
        )
        self.graph_type_var = tk.StringVar(value="Лінійний")
        graph_frame = ttk.Frame(main_frame)
        graph_frame.grid(row=6, column=0, sticky="w")

        for i, text in enumerate(["Лінійний", "Стовпчаста", "Кругова"]):
            ttk.Radiobutton(
                graph_frame, text=text, variable=self.graph_type_var, value=text
            ).grid(row=i, column=0, sticky="w")

        self.plot_button = ttk.Button(
            main_frame,
            text="📊 Побудувати графік",
            command=self.plot_graph,
            state="disabled",
        )
        self.plot_button.grid(row=7, column=0, pady=15, sticky="ew")

        ttk.Button(
            main_frame, text="📈 Середній пульс", command=self.show_average_pulse
        ).grid(row=9, column=0, sticky="ew", pady=3)
        ttk.Button(
            main_frame, text="📉 Аналіз тиску", command=self.analyze_pressure
        ).grid(row=11, column=0, sticky="ew", pady=3)
        ttk.Button(
            main_frame, text="⚖️ Статистика ваги", command=self.analyze_weight
        ).grid(row=12, column=0, sticky="ew", pady=3)
        ttk.Button(
            main_frame, text="🧪 Ефект лікування", command=self.analyze_treatment_effect
        ).grid(row=13, column=0, sticky="ew", pady=(3, 10))

    def load_files(self):
        files = [
            f for f in os.listdir(self.patient_folder) if f.endswith((".xlsx", ".xls"))
        ]
        self.files = files
        self.file_listbox.delete(0, tk.END)
        for file in self.files:
            self.file_listbox.insert(tk.END, file)

    def select_files(self):
        selected_indices = self.file_listbox.curselection()
        selected_files = [self.files[i] for i in selected_indices]

        if not selected_files:
            return

        if self.graph_type_var.get() == "Кругова" and len(selected_files) > 1:
            messagebox.showwarning(
                "Помилка", "Для кругової діаграми можна вибрати лише один файл!"
            )
            return

        self.data = {}
        params = set()

        for file in selected_files:
            file_path = os.path.join(self.patient_folder, file)
            df = pd.read_excel(file_path, header=None)
            param_column = df.iloc[:, 0].dropna().tolist()
            self.data[file] = df
            params.update(param_column)

        self.param_listbox.delete(0, tk.END)
        for param in sorted(params):
            self.param_listbox.insert(tk.END, param)

        self.plot_button["state"] = "normal"

    def plot_graph(self):
        selected_indices = self.param_listbox.curselection()
        selected_params = [self.param_listbox.get(i) for i in selected_indices]
        selected_files = list(self.data.keys())

        if not selected_params:
            return

        graph_type = self.graph_type_var.get()

        if graph_type == "Кругова":
            if len(selected_files) != 1:
                messagebox.showwarning(
                    "Помилка", "Кругова діаграма підтримує лише один файл."
                )
                return

            file = selected_files[0]
            df = self.data[file]
            values, labels = [], []

            for param in selected_params:
                param_row = df[df.iloc[:, 0] == param]
                if not param_row.empty:
                    values.append(param_row.iloc[0, 1])
                    labels.append(param)

            if values:
                plt.figure(figsize=(6, 6))
                plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=140)
                plt.title(f"Кругова діаграма ({file})")
                plt.show()
            return

        plt.figure(figsize=(10, 5))

        if graph_type == "Лінійний":
            for param in selected_params:
                x_labels = []
                y_values = []
                for file in selected_files:
                    df = self.data[file]
                    param_row = df[df.iloc[:, 0] == param]
                    if not param_row.empty:
                        value = param_row.iloc[0, 1]
                        x_labels.append(file)
                        y_values.append(value)
                if y_values:
                    plt.plot(x_labels, y_values, marker="o", linestyle="-", label=param)

            plt.xlabel("Файл")
            plt.ylabel("Значення")
            plt.title("Лінійний графік")
            plt.legend()
            plt.grid(True)

        elif graph_type == "Стовпчаста":
            bar_width = 0.2
            x_indexes = range(len(selected_files))

            for i, param in enumerate(selected_params):
                values = []
                for file in selected_files:
                    df = self.data[file]
                    param_row = df[df.iloc[:, 0] == param]
                    if not param_row.empty:
                        values.append(param_row.iloc[0, 1])
                positions = [x + i * bar_width for x in x_indexes]
                plt.bar(positions, values, width=bar_width, label=param)

            plt.xlabel("Файл")
            plt.ylabel("Значення")
            plt.title("Стовпчаста діаграма")
            plt.xticks(
                [x + (len(selected_params) / 2) * bar_width for x in x_indexes],
                selected_files,
            )
            plt.legend()
            plt.grid(axis="y")

        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

    def show_average_pulse(self):
        try:
            db_path = os.path.abspath("database/medical_system.accdb")
            conn = pyodbc.connect(
                rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};"
            )
            df = pd.read_sql(
                f"SELECT pulse FROM pulse WHERE user_id = {self.patient_id}", conn
            )
            conn.close()

            pulses = df["pulse"].dropna()
            if pulses.empty:
                messagebox.showinfo("Немає даних", "Немає даних про пульс.")
                return

            average = pulses.mean()
            messagebox.showinfo(
                "Середній пульс", f"Середній пульс: {average:.2f} уд/хв"
            )

            if messagebox.askyesno(
                "Графік пульсу", "Бажаєте переглянути графік пульсу?"
            ):
                plt.figure(figsize=(6, 4))
                plt.plot(
                    pulses.index, pulses.values, marker="o", linestyle="-", color="blue"
                )
                plt.title("Пульс з часом")
                plt.xlabel("Вимірювання")
                plt.ylabel("Пульс (уд/хв)")
                plt.grid(True)
                plt.tight_layout()
                plt.show()

        except Exception as e:
            messagebox.showerror("Помилка", f"Не вдалося завантажити пульс:\n{e}")

    def analyze_pressure(self):
        try:
            db_path = os.path.abspath("database/medical_system.accdb")
            conn = pyodbc.connect(
                rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};"
            )
            df = pd.read_sql(
                f"SELECT bpressure, apressure FROM Pressure WHERE user_id = {self.patient_id}",
                conn,
            )
            conn.close()

            if df.empty:
                messagebox.showinfo("Немає даних", "Немає даних про тиск.")
                return

            bp_all = df["bpressure"].dropna()
            ap_all = df["apressure"].dropna()

            msg = ""
            if not bp_all.empty:
                msg += f"📌 Початковий тиск:\n - Дисперсія: {bp_all.var():.2f}\n - Відхилення: {bp_all.std():.2f}\n"
            if not ap_all.empty:
                msg += f"\n📌 Після лікування:\n - Дисперсія: {ap_all.var():.2f}\n - Відхилення: {ap_all.std():.2f}"

            messagebox.showinfo("Стабільність тиску", msg)

            if messagebox.askyesno("Графік тиску", "Бажаєте переглянути графік тиску?"):
                plt.figure(figsize=(8, 4))
                if not bp_all.empty:
                    plt.plot(
                        bp_all.index,
                        bp_all.values,
                        marker="o",
                        label="Початковий тиск",
                        color="red",
                    )
                if not ap_all.empty:
                    plt.plot(
                        ap_all.index,
                        ap_all.values,
                        marker="o",
                        label="Після лікування",
                        color="green",
                    )
                plt.title("Зміна тиску")
                plt.xlabel("Вимірювання")
                plt.ylabel("Тиск")
                plt.legend()
                plt.grid(True)
                plt.tight_layout()
                plt.show()

        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    def analyze_weight(self):
        try:
            db_path = os.path.abspath("database/medical_system.accdb")
            conn = pyodbc.connect(
                rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};"
            )
            df = pd.read_sql(
                f"SELECT weight, sugar FROM WaS WHERE user_id = {self.patient_id}", conn
            )
            conn.close()

            df.columns = [col.strip().lower() for col in df.columns]

            if "sugar" not in df.columns or "weight" not in df.columns:
                messagebox.showerror(
                    "Помилка", "В таблиці немає полів 'weight' або 'sugar'"
                )
                return

            try:
                df["parsed_sugar"] = (
                    df["sugar"]
                    .astype(str)
                    .str.replace(",", ".", regex=False)
                    .astype(float)
                )
            except Exception as e:
                messagebox.showerror(
                    "Помилка", f"Помилка при обробці значень цукру: {e}"
                )
                return

            df = df.dropna(subset=["weight", "parsed_sugar"])

            if df.empty:
                messagebox.showinfo("Недостатньо даних", "Немає коректних значень.")
                return

            avg_weight = df["weight"].mean()
            avg_sugar = df["parsed_sugar"].mean()

            correlation = df["weight"].corr(df["parsed_sugar"])
            correlation_text = f"Коефіцієнт кореляції: {correlation:.2f}\n" + (
                "Є помірна або сильна кореляція між вагою і рівнем цукру."
                if abs(correlation) >= 0.3
                else "Кореляція між вагою і рівнем цукру слабка або відсутня."
            )

            try:
                slope, _ = np.polyfit(df.index, df["weight"], 1)
                if slope > 0.05:
                    trend_text = "Тренд: вага має тенденцію до збільшення."
                elif slope < -0.05:
                    trend_text = "Тренд: вага має тенденцію до зменшення."
                else:
                    trend_text = "Тренд: зміни ваги не мають вираженої тенденції."
            except Exception as e:
                trend_text = f"Помилка при обчисленні тренду ваги: {e}"

            try:
                n = len(df["weight"])
                s = df["weight"].std()
                z = 1.96
                margin_error = z * (s / np.sqrt(n))
                ci_low = avg_weight - margin_error
                ci_high = avg_weight + margin_error
                ci_text = f"З імовірністю 95% вага пацієнта знаходиться в межах {ci_low:.2f} – {ci_high:.2f} кг."
            except Exception as e:
                ci_text = f"Помилка при обчисленні довірчого інтервалу: {e}"

            messagebox.showinfo(
                "Аналіз даних",
                f"Середня вага: {avg_weight:.2f} кг\n"
                f"Середній рівень цукру: {avg_sugar:.2f} ммоль/л\n\n"
                f"{correlation_text}\n\n{trend_text}\n\n📏 {ci_text}",
            )

            if messagebox.askyesno(
                "Графік ваги", "Хочете побачити графік ваги та рівня цукру?"
            ):
                plt.figure(figsize=(6, 4))
                plt.plot(
                    df.index, df["weight"], marker="o", label="Вага", color="orange"
                )
                plt.plot(
                    df.index,
                    df["parsed_sugar"],
                    marker="o",
                    label="Цукор",
                    color="blue",
                )
                plt.title("Динаміка ваги та цукру")
                plt.xlabel("Вимірювання")
                plt.ylabel("Значення")
                plt.legend()
                plt.grid(True)
                plt.tight_layout()
                plt.show()

        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    def analyze_treatment_effect(self):
        try:
            db_path = os.path.abspath("database/medical_system.accdb")
            conn = pyodbc.connect(
                rf"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};"
            )
            df = pd.read_sql(
                f"SELECT bpressure, apressure FROM Pressure WHERE user_id = {self.patient_id}",
                conn,
            )
            conn.close()

            before = df["bpressure"].dropna()
            after = df["apressure"].dropna()

            if len(before) != len(after) or len(before) < 2:
                messagebox.showwarning(
                    "Недостатньо даних", "Потрібно хоча б 2 пари значень тиску."
                )
                return

            avg_before = before.mean()
            avg_after = after.mean()
            messagebox.showinfo(
                "Середні значення",
                f"До лікування: {avg_before:.2f}\nПісля лікування: {avg_after:.2f}",
            )

            if messagebox.askyesno(
                "Графік ефекту", "Бажаєте переглянути графік до/після лікування?"
            ):
                plt.figure(figsize=(6, 4))
                plt.plot(
                    before.index,
                    before.values,
                    marker="o",
                    label="До лікування",
                    color="purple",
                )
                plt.plot(
                    after.index,
                    after.values,
                    marker="o",
                    label="Після лікування",
                    color="green",
                )
                plt.title("До та після лікування")
                plt.xlabel("Вимірювання")
                plt.ylabel("Тиск")
                plt.legend()
                plt.grid(True)
                plt.tight_layout()
                plt.show()

        except Exception as e:
            messagebox.showerror("Помилка", str(e))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("⚠️ Помилка: потрібно передати ID пацієнта.")
        sys.exit(1)

    patient_id = sys.argv[1]
    root = tk.Tk()
    app = ExcelGraphApp(root, patient_id)
    root.mainloop()
