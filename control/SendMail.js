import nodemailer from "nodemail" ;
async function sendUpdateEmail(subscribers, message) {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: process.env.EMAIL,
      pass: process.env.PASSWORD,
    },
  });

  for (let sub of subscribers) {
    await transporter.sendMail({
      from: process.env.EMAIL,
      to: sub.email,
      subject: "Website Update from LearnIQ",
      html: `<p>${message}</p>`,
    });
  }
}
